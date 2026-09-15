"""Candidate-only coordinator for the versioned BuFLO/CS-BuFLO study.

The coordinator validates prospective inputs and delegates sealed export and
evaluation to their dedicated modules.  It never promotes an implementation
from file presence or a partial capture: until a strict all-pass attestation
exists, every action reports the implementation as a candidate.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any

import yaml

from .build_storage import (
    BUILD_EXECUTION_ARTIFACT_TYPE as _BUILD_EXECUTION_ARTIFACT_TYPE,
    BUILD_IMAGE_TAGS,
    BUILD_WSL_HOST_MIN_AVAILABLE_BYTES as _BUILD_WSL_HOST_MIN_AVAILABLE_BYTES,
    _canonical_finite_json_bytes,
    build_completion_path,
    load_stable_build_completion,
    load_stable_build_execution,
    load_stable_build_execution_with_stat,
    validate_build_completion_authority,
    validate_build_execution_envelope,
)
from .fidelity import (
    BUFLO_SCHEDULE_STOP_POLICY,
    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
    BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
    BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
    BUFLO_TERMINAL_SUBCELL_POLICY,
    buflo_terminal_state_valid,
)
from .parameters import BUFLO_STUDY_ID, validate_parameter_artifact
from .util import (
    LAB_ROOT,
    SOURCE_METADATA_KEYS,
    atomic_json,
    load_json,
    require_disjoint_path,
    sha256_file,
    source_metadata,
)

BUILD_EXECUTION_ARTIFACT_TYPE = _BUILD_EXECUTION_ARTIFACT_TYPE
BUILD_WSL_HOST_MIN_AVAILABLE_BYTES = _BUILD_WSL_HOST_MIN_AVAILABLE_BYTES
SCHEMA_VERSION = 1
PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION = 3
LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION = 4
MULTI_ORIGIN_COMPATIBILITY_SCHEMA_VERSION = 2
MULTI_ORIGIN_COMPATIBILITY_ARTIFACT_TYPE = "qcsd-buflo-nine-mode-multi-origin-compatibility"
MULTI_ORIGIN_COMPATIBILITY_CHECKPOINT_TYPE = "qcsd-buflo-multi-origin-compatibility-checkpoint"
MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE = (
    "qcsd-buflo-multi-origin-compatibility-attempt-error"
)
HISTORICAL_MULTI_ORIGIN_V36_RECEIPT_SHA256 = (
    "d2592cef73c65837322f165120777afc699e32505384737a4554614571536fd6"
)
HISTORICAL_MULTI_ORIGIN_V36_SOURCE = {
    "image_digest": "sha256:bfb6b8dd6581225c3ba748f9e6b1537bc5f0b7c8be8dfb3a74f8969134a0b5d4",
    "lab_commit": "b87bf2705e4eb76869d05d4be86a54c3be9da79e",
    "lab_dirty": False,
    "lab_patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "neqo_commit": "fb699636c191e91848ffcce859c43bb4d69f7d94",
    "neqo_dirty": False,
    "neqo_patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "neqo_pinned_commit": "fb699636c191e91848ffcce859c43bb4d69f7d94",
}
PREVIOUS_TIMING_STRESS_SCHEMA_VERSION = 2
TIMING_STRESS_SCHEMA_VERSION = 4
TIMING_STRESS_SEED_NAMESPACE = "buflo-timing-stress-v4"
TIMING_STRESS_ARTIFACT_TYPE = "qcsd-buflo-timing-stress-execution"
TIMING_STRESS_CHECKPOINT_TYPE = "qcsd-buflo-timing-stress-checkpoint"
TIMING_STRESS_ATTEMPT_ERROR_TYPE = "qcsd-buflo-timing-stress-attempt-error"
TIMING_STRESS_ATTEMPT_ERROR_SCHEMA_VERSION = 1
ABORTED_TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION = 5
TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION = 6
CONTROLLED_NETWORK_RECEIPT_SCHEMA_VERSION = 2
KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV = "QCSD_KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_B64"
STUDY_ROOT = LAB_ROOT / "config/buflo-study/v1"
STUDY_PLAN = STUDY_ROOT / "study.json"
TIMING_STRESS_PARAMETERS = STUDY_ROOT / "buflo-timing-stress-v4.json"
TIMING_STRESS_PARAMETERS_PROVENANCE = TIMING_STRESS_PARAMETERS.with_suffix(
    TIMING_STRESS_PARAMETERS.suffix + ".provenance.json"
)
ESTABLISHED_SEVEN_BASELINE = STUDY_ROOT / "established-seven-baseline.json"
ESTABLISHED_SEVEN_BASELINE_SHA256 = (
    "7705ee77b84f0ba4d7521bb8f63fdca69e4ea14580ecc4c41a603c835cfc73ca"
)
CAMPAIGN_ROOT = LAB_ROOT / "config/campaigns"
COHORT_INPUT_ROOT = LAB_ROOT / "artifacts/buflo-study/cohort-inputs"
REFERENCE_ROOT = LAB_ROOT / "config/reference/buflo-csbuflo"
QUALIFICATION_SET_ROOT = LAB_ROOT / "config/chaff-response-qualification-store/sets"
WORKLOADS = (
    "getbootstrap-home-r4",
    "cloudflare-quiche-r4",
    "hyper-basic-client-r3",
    "serde-home-r2",
    "rfc9114-text-r2",
)
COMMON_LIMITS = {
    "timeout_seconds": 120,
    "max_response_bytes": 1_048_576,
    "capture_seconds": 180,
    "capture_megabytes": 64,
    "max_attempts": 3,
    "per_origin_cooldown_seconds": 30,
    "settle_seconds": 1,
}
TIMING_STRESS_VISITS = 12
TIMING_STRESS_INTERVAL_US = 20_000
TIMING_STRESS_MINIMUM_DURATION_US = 100_000_000
TIMING_STRESS_PACKET_SIZE = 1_200
TIMING_STRESS_MAX_EVENTS_PER_DIRECTION = 6_000
TIMING_STRESS_WINDOW_US = 5_000
TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION = 5_001
TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT = 5_000
TIMING_STRESS_MAXIMUM_GUARDS_PER_VISIT = TIMING_STRESS_MAX_EVENTS_PER_DIRECTION - 1
TIMING_STRESS_MINIMUM_INCOMING_BYTES_PER_VISIT = (
    TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION * TIMING_STRESS_PACKET_SIZE
)
TIMING_STRESS_MAXIMUM_INCOMING_BYTES_PER_VISIT = (
    TIMING_STRESS_MAX_EVENTS_PER_DIRECTION * TIMING_STRESS_PACKET_SIZE
)
TIMING_STRESS_MINIMUM_TOTAL_GUARDS = TIMING_STRESS_VISITS * TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT
TIMING_STRESS_MAXIMUM_TOTAL_GUARDS = TIMING_STRESS_VISITS * TIMING_STRESS_MAXIMUM_GUARDS_PER_VISIT
TIMING_STRESS_MINIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION = (
    TIMING_STRESS_VISITS * TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
)
TIMING_STRESS_MAXIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION = (
    TIMING_STRESS_VISITS * TIMING_STRESS_MAX_EVENTS_PER_DIRECTION
)
# The controlled CS-BuFLO qualification needs fresh client-to-server
# application STREAM bytes on which to exercise its first 16 KiB estimator
# boundary.  A deterministic, incompressible-looking literal field keeps this
# driver independent of response chaff.  The value remains well below Neqo's
# 384 KiB QPACK literal limit, while the live encoded-size check below retains
# four complete 600-byte opportunities after the boundary.
CSBUFLO_RATE_DRIVER_HEADER_NAME = "x-qcsd-controlled-csbuflo-rate-driver"
CSBUFLO_RATE_DRIVER_VALUE_BYTES = 32_768
CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES = 16_384
CSBUFLO_RATE_DRIVER_CELL_BYTES = 600
CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS = 4
CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES = (
    CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
    + CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS * CSBUFLO_RATE_DRIVER_CELL_BYTES
)
STAGE_TREATMENTS = {
    "smoke": ("undefended", "buflo", "cs-buflo-cpsp", "cs-buflo-ctsp"),
    "rehearsal": ("undefended", "buflo", "cs-buflo-cpsp", "cs-buflo-ctsp"),
    "formal": ("undefended", "buflo", "cs-buflo"),
}
PARAMETER_FILES = {
    "buflo": ("buflo", LAB_ROOT / "config/defense-params/buflo-live.json"),
    "cs-buflo": ("cs_buflo", LAB_ROOT / "config/defense-params/cs-buflo-ctsp-live.json"),
    "cs-buflo-ctsp": (
        "cs_buflo",
        LAB_ROOT / "config/defense-params/cs-buflo-ctsp-live.json",
    ),
    "cs-buflo-cpsp": (
        "cs_buflo",
        LAB_ROOT / "config/defense-params/cs-buflo-cpsp-live.json",
    ),
}
REFERENCE_FILES = (
    REFERENCE_ROOT / "buflo-ieee-sp-2012-v1.json",
    REFERENCE_ROOT / "csbuflo-wpes-2014-v1.json",
)
CONFORMANCE_RECEIPT = REFERENCE_ROOT / "buflo-csbuflo-conformance-v1.receipt.json"
CONFORMANCE_RECEIPT_SHA256 = "a41d9096a152b5531394fb7f6b4a9936dbe03318da1acc5549d79151b0373dbc"
REFERENCE_EXECUTION_ARTIFACT_TYPE = "qcsd-buflo-csbuflo-reference-execution"
BUILD_EXECUTION_RECEIPT = LAB_ROOT / "artifacts/buflo-study/build-execution-v1.json"
REFERENCE_INPUT_RELATIVE_PATHS = {
    "dyer-paper-pdf": "trafanal.pdf",
    "dyer-folklore-py": "website-fingerprinting/countermeasures/Folklore.py",
    "dyer-config-py": "website-fingerprinting/config.py",
    "dyer-packet-py": "website-fingerprinting/Packet.py",
    "dyer-trace-py": "website-fingerprinting/Trace.py",
    "dyer-webpage-py": "website-fingerprinting/Webpage.py",
    "dyer-overhead-parser-py": "website-fingerprinting/parseResultsFile.py",
    "csbuflo-paper-pdf": "wpes14-csbuflo.pdf",
    "csbuflo-preprint-pdf": "csbuflo-preprint.pdf",
    "csbuflo-misc-h": "CSBuFLO/modified_openssh-5.9p1/misc.h",
    "csbuflo-misc-c": "CSBuFLO/modified_openssh-5.9p1/misc.c",
    "csbuflo-packet-c": "CSBuFLO/modified_openssh-5.9p1/packet.c",
    "csbuflo-clientloop-c": "CSBuFLO/modified_openssh-5.9p1/clientloop.c",
    "csbuflo-serverloop-c": "CSBuFLO/modified_openssh-5.9p1/serverloop.c",
    "csbuflo-cpsp-trace-archive": (
        "CSBuFLO/log_interval_tau_200_20_allmedian_2t_600_CMSM_paddingdone_pairs.tar.gz"
    ),
}
CSBUFLO_AUTHOR_SOURCE_SEGMENT_SHA256 = {
    "client_early_termination_branch": (
        "1b06b7b1590634f8bd14ab80c306f5ef7394f4454466cd618b0cd412630ec3ab"
    ),
    "client_padding_done_define": (
        "efac678f1eafdd00fb1d7612604ea889e3c128872173b11d15904cf1dcf5fcb0"
    ),
    "client_padding_done_notification": (
        "0f7ca5e52466fc92feb486aa834095cd63bac5dfe9c3c323693256540f8f1e21"
    ),
    "client_payload_padding": ("0c1d036e906a28bee0ff87f3b804bef71390cbd3d2689c36408bf853d742e5a0"),
    "client_terminal_branch": ("e4a1b22f2e8eee38d5dfabada56e2fa0970e92829344427da237661f788012c2"),
    "client_total_padding_inactive": (
        "592c65cda56d38764777f51780462cb6c3b504ba9fca8a3777af45af00cbd1fd"
    ),
    "jitter_function": "3d9003b7b04b5028f84d280e6605ddbf4a6a5edca9bfda4f88a035ee9efb3545",
    "server_early_termination_branch": (
        "a1e9dc76f8cc9749f8d16448c7712aab0061de7514eb9a17d4e577fa62a673a2"
    ),
    "server_payload_padding": ("0c1d036e906a28bee0ff87f3b804bef71390cbd3d2689c36408bf853d742e5a0"),
    "server_terminal_branch": ("2b0695a61c87251c5ad5a8055c6689d96425532409bbdf484bc12ee4a57e9e7f"),
    "server_total_padding_inactive": (
        "592c65cda56d38764777f51780462cb6c3b504ba9fca8a3777af45af00cbd1fd"
    ),
    "target_queue_define": ("6f3d0f693f5e7a1ed8afd9fe2f24f9e79e6af66b9d217f7a8316ae719877653a"),
}
CSBUFLO_AUTHOR_SOURCE_SEGMENTS = frozenset(CSBUFLO_AUTHOR_SOURCE_SEGMENT_SHA256)
REQUIRED_REFERENCE_SOURCES = frozenset(
    {
        "dyer-folklore-py",
        "dyer-paper-pdf",
        "dyer-config-py",
        "dyer-packet-py",
        "dyer-trace-py",
        "dyer-webpage-py",
        "dyer-overhead-parser-py",
        "csbuflo-paper-pdf",
        "csbuflo-preprint-pdf",
        "csbuflo-misc-h",
        "csbuflo-misc-c",
        "csbuflo-packet-c",
        "csbuflo-clientloop-c",
        "csbuflo-serverloop-c",
        "csbuflo-cpsp-trace-archive",
    }
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FORMAL_MINIMUM_AVAILABLE_HOURS = 12.5
FORMAL_DISK_SAFETY_MULTIPLIER = 3
FORMAL_BOOTSTRAP_DRAWS = 10_000
FORMAL_BOOTSTRAP_CONTRACT = {
    "draws": FORMAL_BOOTSTRAP_DRAWS,
    "interval": "percentile-95",
    "resampling_unit": "acquisition-block-and-workload",
    "paired_seed": 20260827,
    "attack_seed_policy": "20260827-plus-canonical-attack-index",
}
FORMAL_FAIL_CLOSED_COHORT_VERSION = 15
RUST_BASE_IMAGE = (
    "docker.io/library/rust:1.90-bookworm@"
    "sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f"
)
DEBIAN_BASE_IMAGE = (
    "docker.io/library/debian:bookworm-slim@"
    "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
)
STAGED_CAPTURE_PREREQUISITES = {
    "smoke": ("regression",),
    "rehearsal": ("regression", "smoke"),
    "formal": ("regression", "smoke", "rehearsal"),
}
LOCAL_STAGE_RESULT_NAMES = {
    "controlled": tuple(f"buflo-study-v1-controlled-{rank:02d}-1200" for rank in range(4)),
    "regression": (
        "buflo-study-v1-regression-established-seven-1200",
        "buflo-study-v1-regression-buflo-1200",
        "buflo-study-v1-regression-cs-buflo-1200",
    ),
}
MULTI_ORIGIN_COMPATIBILITY_MODES = (
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
MULTI_ORIGIN_COMPATIBILITY_ORIGINS = (
    "https://qcsd-buflo-server-one:4433",
    "https://qcsd-buflo-server-two:4434",
)
ATTESTATION_ARTIFACT_TYPE = "qcsd-buflo-study-validation-attestation"
VALIDATED_STATUS = "validated-client-only-qcsd-adaptation"
VALIDATED_STATUS_DESCRIPTION = "validated client-only QCSD adaptation"
HISTORICAL_SNAPSHOT_ARTIFACT_TYPE = "qcsd-buflo-historical-corpus-snapshot"
QUALIFICATION_RECEIPT_ARTIFACT_TYPE = "qcsd-buflo-study-qualification"
CODE_GATE_ARTIFACT_TYPE = "qcsd-buflo-study-code-gate"
COMPARISON_REVIEW_ARTIFACT_TYPE = "qcsd-buflo-study-comparison-review"
CAPTURE_ADMISSION_ARTIFACT_TYPE = "qcsd-buflo-study-capture-admission"
COHORT_MANIFEST_ARTIFACT_TYPE = "qcsd-buflo-study-formal-cohort"
HARD_GATE_IDENTITIES = (
    "reference-receipts-and-clean-room-oracles-pass",
    "runtime-unit-integration-and-parameter-binding-tests-pass",
    "nine-mode-regression-is-18-of-18-correct-and-fidelity-eligible",
    "controlled-clean-and-netem-matrix-is-160-of-160-correct-and-fidelity-eligible",
    "event-guards-misses-shortfalls-size-errors-and-unresolved-incoming-bytes-are-zero",
    "ctsp-and-cpsp-resolve-to-distinct-sealed-parameter-hashes-and-padding-modes",
    "public-smoke-is-20-of-20-correct-and-fidelity-eligible",
    "public-rehearsal-is-40-of-40-correct-and-fidelity-eligible",
    "formal-campaigns-are-frozen-before-capture-and-produce-1500-of-1500-eligible-samples",
    (
        "paired-overhead-latency-tail-goodput-and-client-correctness-are-reported-"
        "with-95-percent-cluster-bootstrap-intervals"
    ),
    (
        "paper-metric-and-classifier-comparisons-are-reconciled-with-observation-"
        "layer-and-client-only-limitations"
    ),
    ("historical-corpus-guard-is-unchanged-and-sealed-results-handoff-evaluation-receipts-verify"),
)
RUST_CODE_GATE_ROOT = Path(
    os.environ.get("QCSD_RUST_CODE_GATE_ROOT", "/usr/share/qcsd-lab/rust-code-gate")
)
TOP_LEVEL_PLAN_KEYS = {
    "schema_version",
    "study_id",
    "default_cohort_version",
    "qualification_set_pattern",
    "implementation_status",
    "promotion_rule",
    "implementation_baselines",
    "established_seven_baseline_oracle",
    "profile",
    "qualification_set",
    "workloads",
    "treatments",
    "controlled",
    "regression",
    "timing_stress",
    "public_stages",
    "capture_admission",
    "hard_gates",
    "historical_corpus_guard",
    "immutability",
}


@dataclass(frozen=True)
class StudyActionResult:
    action: str
    status: str
    implementation_status: str
    details: Mapping[str, Any]
    blockers: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["blockers"] = list(self.blockers)
        return value


def load_study_plan(path: Path = STUDY_PLAN) -> dict[str, Any]:
    """Load and validate the immutable version-one capture plan."""

    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"BuFLO study plan is not a regular file: {path}")
    value = load_json(path)
    if not isinstance(value, dict):
        raise TypeError("BuFLO study plan must be a JSON object")
    validate_study_plan(value)
    return value


def validate_study_plan(value: Mapping[str, Any]) -> None:
    """Validate sample counts, stages, promotion gates, and immutability policy."""

    if set(value) != TOP_LEVEL_PLAN_KEYS:
        raise ValueError("BuFLO study plan fields are invalid")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("study_id") != BUFLO_STUDY_ID
        or value.get("default_cohort_version") != 1
        or value.get("qualification_set_pattern") != "buflo-study-public5-v{cohort_version}"
        or value.get("implementation_status") != "candidate"
        or value.get("promotion_rule") != "all-gates-pass-with-no-waivers"
        or value.get("implementation_baselines")
        != {
            "lab_commit": "8988a48a8e43cc9d47505cae12ee7758bc7fa5ee",
            "neqo_commit": "6aceaac85243d6e0e34354108e010705d3c83088",
        }
        or value.get("established_seven_baseline_oracle")
        != {
            "path": "config/buflo-study/v1/established-seven-baseline.json",
            "sha256": ESTABLISHED_SEVEN_BASELINE_SHA256,
        }
        or value.get("profile") != "research-1200"
        or value.get("qualification_set") != "buflo-study-public5-v1"
        or tuple(value.get("workloads", ())) != WORKLOADS
    ):
        raise ValueError("BuFLO study identity or candidate status is invalid")

    treatments = value.get("treatments")
    if not isinstance(treatments, list) or not treatments:
        raise ValueError("BuFLO study treatments are missing")
    names = [item.get("name") for item in treatments if isinstance(item, dict)]
    if len(names) != len(treatments) or len(names) != len(set(names)):
        raise ValueError("BuFLO study treatment identities are invalid")
    required_names = {
        "undefended",
        "buflo",
        "cs-buflo",
        "cs-buflo-ctsp",
        "cs-buflo-cpsp",
    }
    if set(names) != required_names:
        raise ValueError("BuFLO study treatment registry is incomplete")
    by_name = {item["name"]: item for item in treatments}
    for name, expected_kind in {
        "undefended": "none",
        "buflo": "buflo",
        "cs-buflo": "cs_buflo",
        "cs-buflo-ctsp": "cs_buflo",
        "cs-buflo-cpsp": "cs_buflo",
    }.items():
        if by_name[name].get("kind") != expected_kind:
            raise ValueError(f"BuFLO study treatment {name} has the wrong runtime kind")
    if by_name["cs-buflo"].get("paper_variant") != "CTSP":
        raise ValueError("formal CS-BuFLO must be the canonical CTSP treatment")
    if by_name["cs-buflo-ctsp"].get("paper_variant") != "CTSP":
        raise ValueError("CS-BuFLO CTSP alias is invalid")
    if by_name["cs-buflo-cpsp"].get("paper_variant") != "CPSP":
        raise ValueError("CS-BuFLO CPSP alias is invalid")
    for name, (_kind, expected_path) in PARAMETER_FILES.items():
        if name not in by_name:
            continue
        relative = by_name[name].get("parameters")
        if (
            not isinstance(relative, str)
            or (STUDY_PLAN.parent / relative).resolve() != expected_path
        ):
            raise ValueError(f"BuFLO study treatment {name} parameter path is invalid")

    controlled = value.get("controlled")
    if not isinstance(controlled, dict) or set(controlled) != {
        "workloads",
        "visits_per_cell",
        "expected_samples",
        "treatments",
        "netem_profiles",
    }:
        raise ValueError("controlled BuFLO matrix is invalid")
    netem = controlled.get("netem_profiles")
    if (
        tuple(controlled.get("workloads", ())) != ("local-small", "local-large")
        or tuple(controlled.get("treatments", ())) != STAGE_TREATMENTS["smoke"]
        or controlled.get("visits_per_cell") != 5
        or not isinstance(netem, list)
        or len(netem) != 4
        or any(
            not isinstance(item, dict)
            or set(item) != {"id", "client_qdisc", "server_qdisc"}
            or item["client_qdisc"] != item["server_qdisc"]
            for item in netem
        )
        or len({item["id"] for item in netem}) != 4
    ):
        raise ValueError("controlled netem matrix is malformed")
    controlled_total = (
        len(controlled["workloads"])
        * len(controlled["treatments"])
        * len(netem)
        * controlled["visits_per_cell"]
    )
    if controlled.get("expected_samples") != controlled_total or controlled_total != 160:
        raise ValueError("controlled netem sample count is invalid")
    expected_netem = (
        ("clean", "none"),
        ("symmetric-50ms-rtt", "netem delay 25ms"),
        (
            "symmetric-5mbit-50ms-rtt-100-packet-queue",
            "netem delay 25ms rate 5mbit limit 100",
        ),
        ("symmetric-1pct-loss-50ms-rtt", "netem delay 25ms loss 1%"),
    )
    if tuple((item["id"], item["client_qdisc"]) for item in netem) != expected_netem:
        raise ValueError("controlled netem values differ from the predeclared study matrix")

    regression = value.get("regression")
    regression_treatments = (
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
    if (
        not isinstance(regression, dict)
        or set(regression)
        != {
            "workloads",
            "visits_per_treatment",
            "expected_samples",
            "treatments",
            "formal_evidence",
        }
        or tuple(regression.get("workloads", ())) != ("local-small", "local-large")
        or regression.get("visits_per_treatment") != 1
        or tuple(regression.get("treatments", ())) != regression_treatments
        or regression.get("expected_samples") != 18
        or regression.get("formal_evidence") is not False
    ):
        raise ValueError("nine-mode regression matrix is invalid")

    timing_stress = value.get("timing_stress")
    expected_timing_stress = {
        "execution_stage": "mandatory-regression-prelude",
        "evidence_class": "timing-stress-nonformal-excluded",
        "workload": "complex-two-origin",
        "treatment": "buflo",
        "network_profile": "clean",
        "visits": TIMING_STRESS_VISITS,
        "max_attempts": 1,
        "authoritative_checkpoint": "experiment.json",
        "interval_us": TIMING_STRESS_INTERVAL_US,
        "minimum_duration_us": TIMING_STRESS_MINIMUM_DURATION_US,
        "packet_size": TIMING_STRESS_PACKET_SIZE,
        "max_events_per_direction": TIMING_STRESS_MAX_EVENTS_PER_DIRECTION,
        "strict_half_open_window_us": TIMING_STRESS_WINDOW_US,
        "contract_schema_version": TIMING_STRESS_SCHEMA_VERSION,
        "cadence_semantics": "inclusive-minimum-prefix-plus-bounded-terminal-whole-cell-drain",
        "mandatory_prefix_opportunities_per_direction": (
            TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
        ),
        "minimum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": (
            TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT
        ),
        "maximum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": (
            TIMING_STRESS_MAXIMUM_GUARDS_PER_VISIT
        ),
        "minimum_incoming_bytes_per_visit": TIMING_STRESS_MINIMUM_INCOMING_BYTES_PER_VISIT,
        "maximum_incoming_bytes_per_visit": TIMING_STRESS_MAXIMUM_INCOMING_BYTES_PER_VISIT,
        "minimum_kernel_timed_outgoing_releases_after_tick_zero": (
            TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        ),
        "maximum_kernel_timed_outgoing_releases_after_tick_zero": (
            TIMING_STRESS_MAXIMUM_TOTAL_GUARDS
        ),
        "minimum_opportunities_per_direction": (
            TIMING_STRESS_MINIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        ),
        "maximum_opportunities_per_direction": (
            TIMING_STRESS_MAXIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        ),
        "logical_order_evidence": "direction-target-slot-identity",
        "physical_row_order": "terminal-resolution-order-not-dispatch-order",
        "terminal_schedule_stop_policy": (
            "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
            "then_drain_already_advertised_incoming_credit"
        ),
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 11,
        "legacy_userspace_exact_release_projection": (
            "schema-10-compatibility-fields-retained-and-neutral"
        ),
        "kernel_tx_runner_receipt_schema_version": 2,
        "kernel_tx_evidence_schema_version": 1,
        "observer_topology_receipt_schema_version": 1,
        "physical_outgoing_observer": "router-ingress-post-client-veth-pre-netem",
        "tick_zero_physical_observation_required": True,
        "formal_evidence": False,
    }
    if timing_stress != expected_timing_stress:
        raise ValueError("BuFLO timing-stress contract is invalid")

    stages = value.get("public_stages")
    if not isinstance(stages, dict) or set(stages) != set(STAGE_TREATMENTS):
        raise ValueError("BuFLO public stages are invalid")
    expected = {
        "smoke": (1, 1, 20, False),
        "rehearsal": (1, 2, 40, False),
        "formal": (10, 10, 1_500, True),
    }
    for stage, (blocks, visits, sample_count, formal) in expected.items():
        record = stages[stage]
        expected_stage_fields = {
            "blocks",
            "seeds",
            "visits_per_workload",
            "expected_samples",
            "formal_evidence",
            "treatments",
            "campaigns",
        }
        if formal:
            expected_stage_fields.update({"bootstrap_draws", "bootstrap_contract"})
        if not isinstance(record, dict) or set(record) != expected_stage_fields:
            raise ValueError(f"BuFLO {stage} stage fields are invalid")
        calculated = blocks * len(WORKLOADS) * visits * len(STAGE_TREATMENTS[stage])
        if (
            record["blocks"] != blocks
            or record["visits_per_workload"] != visits
            or record["expected_samples"] != sample_count
            or calculated != sample_count
            or record["formal_evidence"] is not formal
            or tuple(record["treatments"]) != STAGE_TREATMENTS[stage]
            or len(record["campaigns"]) != blocks
            or len(record["seeds"]) != blocks
            or len(set(record["seeds"])) != blocks
            or (
                formal
                and (
                    record.get("bootstrap_draws") != FORMAL_BOOTSTRAP_DRAWS
                    or record.get("bootstrap_contract") != FORMAL_BOOTSTRAP_CONTRACT
                )
            )
        ):
            raise ValueError(f"BuFLO {stage} stage matrix is invalid")

    if value.get("capture_admission") != {
        "staged_prerequisites": {
            stage: list(prerequisites)
            for stage, prerequisites in STAGED_CAPTURE_PREREQUISITES.items()
        },
        "reference_gate": "isolated-create-only-conformance-receipt",
        "formal_code_gate": "validated-create-only-code-gate-receipt",
        "source_lineage": "one-exact-clean-collection-image",
        "formal_minimum_available_hours": FORMAL_MINIMUM_AVAILABLE_HOURS,
        "formal_disk_safety_multiplier": FORMAL_DISK_SAFETY_MULTIPLIER,
        "formal_disk_projection_basis": "verified-smoke-plus-rehearsal-bytes-per-sample",
    }:
        raise ValueError("BuFLO staged capture admission contract is invalid")

    gates = value.get("hard_gates")
    if gates != list(HARD_GATE_IDENTITIES):
        raise ValueError("BuFLO hard gates differ from the immutable ordered identities")
    historical = value.get("historical_corpus_guard")
    if historical != {
        "root": "handoffs/classifier-multiorigin5-v2",
        "validation": "closed-sha256-inventory-before-and-after-formal",
        "files": {
            "SHA256SUMS": ("85bfd88be6c2105201ec7ff3eb87a743e378bd748a9c2097db2fb227875ec2d7"),
            "dataset.json": ("46289f368912ee6e90314578814b821eb0dfeadcd794d3422c1af3599623317b"),
            "samples.jsonl": ("5974ab9c582793501c558ec294bea4e3afb01bf57039f990fceba33fb0b1e15f"),
        },
        "historical_exporter": {
            "path": "tools/classifier_handoff.py",
            "sha256": ("f91964df8b6af3b1d89a8c2ff2de1997a59e9ffe36124fa8e20c694515152a72"),
        },
    }:
        raise ValueError("historical corpus immutability guard is invalid")
    immutability = value.get("immutability")
    if immutability != {
        "historical_campaigns_and_results": "read-only",
        "smoke_rehearsal_and_controlled": "excluded-from-formal",
        "formal_seed_selection": "prospective-plan-only",
        "resume_checkpoint": "experiment.json",
        "accepted_samples": "never-rewritten",
    }:
        raise ValueError("BuFLO study immutability contract is invalid")


def validate_established_seven_baseline() -> dict[str, Any]:
    """Recheck the pre-change seven-mode configuration and behavior oracles."""

    if (
        ESTABLISHED_SEVEN_BASELINE.is_symlink()
        or not ESTABLISHED_SEVEN_BASELINE.is_file()
        or sha256_file(ESTABLISHED_SEVEN_BASELINE) != ESTABLISHED_SEVEN_BASELINE_SHA256
    ):
        raise ValueError("established-seven baseline oracle digest is invalid")
    value = load_json(ESTABLISHED_SEVEN_BASELINE)
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "artifact_type",
        "baseline_commits",
        "derivation",
        "defense_identity_projection",
        "live_profile_established_projection",
        "runtime_inputs",
        "behavior_oracles",
    }:
        raise ValueError("established-seven baseline oracle schema is invalid")
    if (
        value["schema_version"] != 1
        or value["artifact_type"] != "qcsd-established-seven-baseline-oracle"
        or value["baseline_commits"]
        != {
            "lab": "8988a48a8e43cc9d47505cae12ee7758bc7fa5ee",
            "neqo": "6aceaac85243d6e0e34354108e010705d3c83088",
        }
        or value["derivation"]
        != {
            "method": (
                "git-show-raw-bytes-and-TOML-projection-from-the-two-clean-baseline-commits"
            ),
            "status": "immutable-pre-change-oracle",
        }
    ):
        raise ValueError("established-seven baseline identity is invalid")
    expected_identities = [
        ["undefended", "none"],
        ["static", "static"],
        ["front", "front"],
        ["tamaraw", "tamaraw"],
        ["traffic-morphing", "traffic_morphing"],
        ["wtf-pad", "wtf_pad"],
        ["walkie-talkie", "walkie_talkie"],
    ]
    from .defenses import DEFENSE_ORDER, DEFENSE_RUNTIME_KINDS

    current_identities = [[name, DEFENSE_RUNTIME_KINDS[name]] for name in DEFENSE_ORDER[:7]]
    if value["defense_identity_projection"] != expected_identities or current_identities != (
        expected_identities
    ):
        raise ValueError("established-seven defense identities changed from baseline")
    expected_runtime_inputs = {
        "config/defense-params/static-control-1200.csv": (
            "d38a7d69bd221b5e113f1d3aacfc501a28aeff84c59bd9ab0e224391e9f35611"
        ),
        "config/defense-params/traffic-morphing-live.json": (
            "7010a465480fe2450fb97b987082108b0f3616c2f0287b92ef82e06837071d52"
        ),
        "config/defense-params/traffic-morphing-live.json.provenance.json": (
            "66ea0a621c4b83031b9f8761fbc25bb51e1500079c3f4fa4883dabe4ed202244"
        ),
        "config/defense-params/walkie-talkie-live.json": (
            "dbb050654ae87f2006fcdc39409dc41ca3f4988d6089bb4c3623119adecfc6c4"
        ),
        "config/defense-params/walkie-talkie-live.json.provenance.json": (
            "607ee84b02db39acf27cefdd351fa72f7f33a56660c9f89b62f2b2c9cbd20f38"
        ),
        "config/defense-params/wtfpad-live.json": (
            "e86aeaabd08c72977697943b1903f3258a884ec363c73d035ae6bd646c136e43"
        ),
        "config/defense-params/wtfpad-live.json.provenance.json": (
            "52d936ce07746d63a0fa10e32a53dac2fcfbc7aeff0cc3569c824d59e0abb4a2"
        ),
    }
    if value["runtime_inputs"] != expected_runtime_inputs or any(
        sha256_file(LAB_ROOT / relative) != digest
        for relative, digest in expected_runtime_inputs.items()
    ):
        raise ValueError("established-seven runtime inputs changed from baseline")
    expected_unchanged_sources = {
        "neqo-csdef/src/defense/front.rs": (
            "4aee5a900814743266110bf2add853731475faa03cedb97cbf412fc15dc7ff9a"
        ),
        "neqo-csdef/src/defense/static_schedule.rs": (
            "527fb65a370a7aa31ff07c92e8e8e2b520a21f113ddd064f69a50af2e3179ea2"
        ),
        "neqo-csdef/src/defense/tamaraw.rs": (
            "7bf2622ae6662fcead939928b9a0c335fdc28d2477397352e33f8e24bec12d79"
        ),
    }
    expected_goldens = {
        "neqo-csdef/tests/data/walkie-talkie-continuation.json": (
            "6bd9dfdf54cfd5db5636b5c07fe6aec86ab17679cdf5e78df2efce7ffebacd12"
        ),
        "neqo-csdef/tests/data/walkie-talkie-golden.json": (
            "3396f5efa58d50f410c67b6e7b7667059e2fb53cda11a3710f14d2e56d335703"
        ),
        "neqo-csdef/tests/data/wtf-pad-golden.json": (
            "b89dd044a2f1a2e79e6a9f6da9bbe2be9632aff6ecce5c691adbbb2bc8ff81a4"
        ),
    }
    behavior = value["behavior_oracles"]
    expected_regression = {
        "campaign_name": "buflo-study-v1-regression-established-seven-1200",
        "evidence_class": "controlled-test-only-nonformal",
        "expected_samples": 14,
        "required_treatments": [row[0] for row in expected_identities],
        "required_verdict": "14-of-14-response-correct-and-intrinsic-fidelity-eligible",
        "rust_test_binding": "cargo test -p neqo-csdef --locked",
    }
    if (
        not isinstance(behavior, Mapping)
        or set(behavior)
        != {
            "byte_identical_rust_defenses",
            "byte_identical_golden_vectors",
            "live_regression",
        }
        or behavior["byte_identical_rust_defenses"] != expected_unchanged_sources
        or behavior["byte_identical_golden_vectors"] != expected_goldens
        or behavior["live_regression"] != expected_regression
    ):
        raise ValueError("established-seven behavior oracle is invalid")
    for relative, digest in {**expected_unchanged_sources, **expected_goldens}.items():
        if sha256_file(LAB_ROOT / "neqo-qcsd" / relative) != digest:
            raise ValueError(f"established-seven baseline behavior changed: {relative}")
    profile = tomllib.loads(
        (LAB_ROOT / "neqo-qcsd/neqo-csdef/profiles/live.toml").read_text(encoding="utf-8")
    )
    projection = {
        key: profile[key]
        for key in (
            "schema_version",
            "controller",
            "front",
            "tamaraw",
            "traffic_morphing",
            "wtf_pad",
            "walkie_talkie",
        )
    }
    if projection != value["live_profile_established_projection"]:
        raise ValueError("established-seven live profile projection changed from baseline")
    return {
        "path": str(ESTABLISHED_SEVEN_BASELINE),
        "sha256": ESTABLISHED_SEVEN_BASELINE_SHA256,
        "defenses": [row[0] for row in expected_identities],
        "runtime_inputs": len(expected_runtime_inputs),
        "behavior_oracles": len(expected_unchanged_sources) + len(expected_goldens) + 1,
        "passed": True,
    }


def _cohort_version(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("cohort version must be a positive integer")
    return value


def build_execution_receipt_path(cohort_version: int = 1) -> Path:
    """Return the sole create-only build receipt path for one evidence cohort."""

    version = _cohort_version(cohort_version)
    if version == 1:
        return BUILD_EXECUTION_RECEIPT
    return LAB_ROOT / f"artifacts/buflo-study/build-execution-v{version}.json"


def qualification_set_for_cohort(cohort_version: int) -> str:
    version = _cohort_version(cohort_version)
    pattern = load_study_plan()["qualification_set_pattern"]
    return str(pattern).format(cohort_version=version)


def formal_evaluation_contract_for_cohort(
    cohort_version: int,
) -> dict[str, Any] | None:
    """Return the prospective formal evaluator contract for fail-closed cohorts."""

    version = _cohort_version(cohort_version)
    if version < FORMAL_FAIL_CLOSED_COHORT_VERSION:
        return None
    return dict(FORMAL_BOOTSTRAP_CONTRACT)


def _rendered_campaign_bytes(path: Path, *, cohort_version: int) -> bytes:
    version = _cohort_version(cohort_version)
    source = path.read_bytes()
    if version == 1:
        return source
    old = b"chaff_qualification_set: buflo-study-public5-v1\n"
    if source.count(old) != 1:
        raise ValueError("BuFLO campaign has no unique qualification-set declaration")
    replacement = f"chaff_qualification_set: {qualification_set_for_cohort(version)}\n".encode()
    return source.replace(old, replacement)


def _resolved_campaign_path(path: Path, *, cohort_version: int, create: bool) -> Path:
    version = _cohort_version(cohort_version)
    if version == 1:
        return path
    root = COHORT_INPUT_ROOT / f"v{version}" / "campaigns"
    if root.is_symlink() or COHORT_INPUT_ROOT.is_symlink():
        raise ValueError("cohort campaign root cannot be a symlink")
    destination = root / path.name
    encoded = _rendered_campaign_bytes(path, cohort_version=version)
    if create:
        root.mkdir(parents=True, exist_ok=True)
        _create_or_verify_bytes(destination, encoded, "resolved cohort campaign")
    if destination.is_symlink() or not destination.is_file():
        raise ValueError(f"resolved cohort campaign is absent: {destination}")
    if destination.read_bytes() != encoded:
        raise ValueError("resolved cohort campaign differs from its deterministic source")
    return destination


def campaign_paths(
    stage: str | None = None,
    block: int | None = None,
    *,
    cohort_version: int = 1,
    create_resolved: bool = False,
) -> tuple[Path, ...]:
    plan = load_study_plan()
    if stage is None:
        if block is not None:
            raise ValueError("a formal block requires stage=formal")
        names = [
            name
            for candidate in ("smoke", "rehearsal", "formal")
            for name in plan["public_stages"][candidate]["campaigns"]
        ]
    else:
        if stage not in STAGE_TREATMENTS:
            raise ValueError("study stage must be smoke, rehearsal, or formal")
        names = list(plan["public_stages"][stage]["campaigns"])
        if block is not None:
            if stage != "formal" or not 1 <= block <= len(names):
                raise ValueError("formal block must be between 1 and 10")
            names = [names[block - 1]]
    return tuple(
        _resolved_campaign_path(
            CAMPAIGN_ROOT / name,
            cohort_version=cohort_version,
            create=create_resolved,
        )
        for name in names
    )


def validate_campaign_matrix(
    stage: str | None = None,
    *,
    cohort_version: int = 1,
) -> dict[str, Any]:
    """Validate every prospective YAML without requiring unpublished qualification evidence."""

    version = _cohort_version(cohort_version)
    plan = load_study_plan()
    if stage in {"controlled", "regression"}:
        cells = generated_stage_cells(stage, plan=plan)
        return {
            "schema_version": SCHEMA_VERSION,
            "stage": stage,
            "cohort_version": version,
            "qualification_set": qualification_set_for_cohort(version),
            "generated_matrix_sha256": _canonical_digest(cells),
            "samples": len(cells),
            "cells": list(cells),
        }
    stages = (stage,) if stage is not None else ("smoke", "rehearsal", "formal")
    total = 0
    records = []
    formal_positions: dict[tuple[str, str], list[int]] = {}
    for candidate in stages:
        if candidate not in STAGE_TREATMENTS:
            raise ValueError("study stage must be smoke, rehearsal, or formal")
        spec = plan["public_stages"][candidate]
        for index, (name, seed) in enumerate(zip(spec["campaigns"], spec["seeds"], strict=True)):
            path = _resolved_campaign_path(
                CAMPAIGN_ROOT / name,
                cohort_version=version,
                create=version != 1,
            )
            value = _campaign_document(path)
            _validate_campaign_document(
                value,
                candidate,
                index,
                seed,
                plan,
                qualification_set=qualification_set_for_cohort(version),
            )
            count = sum(value["workloads"].values()) * len(value["defenses"])
            total += count
            records.append({"path": str(path), "sha256": sha256_file(path), "samples": count})
            if candidate == "formal":
                _accumulate_positions(formal_positions, value)
        if (
            sum(record["samples"] for record in records if f"-{candidate}" in record["path"])
            != spec["expected_samples"]
        ):
            raise ValueError(f"BuFLO {candidate} campaign sample count drifted")
    checked_in = set(CAMPAIGN_ROOT.glob("buflo-study-v1-*.yml"))
    declared = {CAMPAIGN_ROOT / path.name for path in campaign_paths()}
    if stage is None and checked_in != declared:
        raise ValueError("checked-in BuFLO campaign set differs from the versioned plan")
    if formal_positions and any(
        max(counts) - min(counts) > 1 for counts in formal_positions.values()
    ):
        raise ValueError("formal defense-order positions are not prospectively balanced")
    return {
        "schema_version": SCHEMA_VERSION,
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
        "campaigns": records,
        "samples": total,
        "formal_position_counts": {
            f"{workload}:{treatment}": counts
            for (workload, treatment), counts in sorted(formal_positions.items())
        },
    }


def generated_stage_cells(
    stage: str, *, plan: Mapping[str, Any] | None = None
) -> tuple[dict[str, Any], ...]:
    """Generate the frozen local controlled/regression cells without executing them."""

    resolved_plan = load_study_plan() if plan is None else plan
    cells: list[dict[str, Any]] = []
    if stage == "controlled":
        spec = resolved_plan["controlled"]
        treatments = tuple(spec["treatments"])
        workload_ranks = {workload: rank for rank, workload in enumerate(sorted(spec["workloads"]))}
        for workload in spec["workloads"]:
            workload_rank = workload_ranks[workload]
            for netem_rank, netem in enumerate(spec["netem_profiles"]):
                for visit in range(spec["visits_per_cell"]):
                    phase = (workload_rank + netem_rank + visit) % len(treatments)
                    order = treatments[phase:] + treatments[:phase]
                    for position, treatment in enumerate(order):
                        cells.append(
                            {
                                "sample_index": len(cells),
                                "workload": workload,
                                "visit": visit,
                                "treatment": treatment,
                                "treatment_position": position,
                                "netem_profile": netem["id"],
                                "client_qdisc": netem["client_qdisc"],
                                "server_qdisc": netem["server_qdisc"],
                            }
                        )
        if len(cells) != spec["expected_samples"]:
            raise ValueError("controlled generated matrix sample count drifted")
    elif stage == "regression":
        spec = resolved_plan["regression"]
        workload_ranks = {workload: rank for rank, workload in enumerate(sorted(spec["workloads"]))}
        for workload in spec["workloads"]:
            workload_rank = workload_ranks[workload]
            treatments = tuple(spec["treatments"])
            order = treatments[workload_rank:] + treatments[:workload_rank]
            for position, treatment in enumerate(order):
                cells.append(
                    {
                        "sample_index": len(cells),
                        "workload": workload,
                        "visit": 0,
                        "treatment": treatment,
                        "treatment_position": position,
                        "netem_profile": "clean",
                        "client_qdisc": "none",
                        "server_qdisc": "none",
                    }
                )
        if len(cells) != spec["expected_samples"]:
            raise ValueError("regression generated matrix sample count drifted")
    else:
        raise ValueError("generated stage must be controlled or regression")
    if [cell["sample_index"] for cell in cells] != list(range(len(cells))):
        raise ValueError("generated stage sample indexes are not contiguous")
    return tuple(cells)


def validate_controlled_campaign_receipt(
    value: Any,
    *,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the qdisc observations frozen into one local study campaign."""

    historical_keys = {
        "schema_version",
        "stage",
        "netem_profile",
        "netem_rank",
        "client_qdisc",
        "server_qdisc",
        "workload_aliases",
        "treatment_order",
        "evidence_class",
        "network",
    }
    previous_keys = historical_keys | {"fixture_scope"}
    current_keys = previous_keys | {"cohort_version"}
    stress_bound_keys = current_keys | {"timing_stress"}
    fields = frozenset(value) if isinstance(value, Mapping) else frozenset()
    schema_version = value.get("schema_version") if isinstance(value, Mapping) else None
    if schema_version == ABORTED_TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION:
        raise ValueError(
            "controlled campaign receipt schema 5 was reserved by failed cohorts and has "
            "no completed timing-stress execution receipt"
        )
    if not isinstance(value, Mapping) or not (
        (schema_version == SCHEMA_VERSION and fields == frozenset(historical_keys))
        or (schema_version == 2 and fields == frozenset(previous_keys))
        or (
            schema_version
            in {
                PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
                LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
            }
            and fields == frozenset(current_keys)
        )
        or (
            schema_version == TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION
            and fields == frozenset(stress_bound_keys)
        )
    ):
        raise ValueError("controlled campaign receipt fields are invalid")
    stage = value["stage"]
    if stage not in {"controlled", "regression"}:
        raise ValueError("controlled campaign receipt stage is invalid")
    plan = load_study_plan()
    if stage == "controlled":
        profiles = plan["controlled"]["netem_profiles"]
        rank = value["netem_rank"]
        if type(rank) is not int or not 0 <= rank < len(profiles):
            raise ValueError("controlled campaign netem rank is invalid")
        expected = profiles[rank]
    else:
        expected = {"id": "clean", "client_qdisc": "none", "server_qdisc": "none"}
        if value["netem_rank"] != 0:
            raise ValueError("regression campaign must use clean networking")
    expected_aliases = (
        {"local-large": "local-large", "local-small": "local-small"}
        if stage == "controlled"
        else {"complex": "local-large", "simple": "local-small"}
    )
    expected_treatments = (
        STAGE_TREATMENTS["smoke"]
        if stage == "controlled"
        else tuple(plan["regression"]["treatments"])
    )
    expected_fixture_scope = "controlled-live-manifests-including-two-origin-local-large"
    if stage == "regression":
        expected_fixture_scope = (
            "single-origin-prefix-regression-plus-bound-two-origin-nine-mode-compatibility"
            if schema_version
            in {
                LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
                TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION,
            }
            else "same-origin-regression-surrogates"
        )
    if (
        value["netem_profile"] != expected["id"]
        or value["client_qdisc"] != expected["client_qdisc"]
        or value["server_qdisc"] != expected["server_qdisc"]
        or value["evidence_class"] != "controlled-test-only-nonformal"
        or (
            schema_version
            in {
                2,
                PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
                LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
                TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION,
            }
            and value["fixture_scope"] != expected_fixture_scope
        )
        or value["workload_aliases"] != expected_aliases
        or tuple(value["treatment_order"]) != expected_treatments
    ):
        raise ValueError("controlled campaign matrix binding is invalid")
    _validate_network_receipt(
        value["network"],
        client_qdisc=expected["client_qdisc"],
        server_qdisc=expected["server_qdisc"],
        campaign_schema_version=schema_version,
        cohort_version=value.get("cohort_version")
        if schema_version
        in {
            PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
            LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
            TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION,
        }
        else None,
    )
    if schema_version == TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION:
        if stage != "regression":
            raise ValueError("timing-stress binding is valid only for regression campaigns")
        stress = _validate_timing_stress_binding(
            value["timing_stress"],
            expected_source=_expected_collection_source,
        )
        if (
            stress["cohort_version"] != value["cohort_version"]
            or stress["network"] != value["network"]
            or stress["source"]["image_digest"] != value["network"].get("image_digest")
        ):
            raise ValueError("regression timing-stress cohort, image, or network binding differs")
    return dict(value)


def _validate_network_receipt(
    value: Any,
    *,
    client_qdisc: str,
    server_qdisc: str,
    campaign_schema_version: int,
    cohort_version: int | None,
) -> None:
    if campaign_schema_version in {
        PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION,
    }:
        _validate_shared_router_network_receipt(
            value,
            client_qdisc=client_qdisc,
            server_qdisc=server_qdisc,
            cohort_version=cohort_version,
        )
        return
    _validate_legacy_network_receipt(
        value,
        client_qdisc=client_qdisc,
        server_qdisc=server_qdisc,
    )


def _validate_legacy_network_receipt(value: Any, *, client_qdisc: str, server_qdisc: str) -> None:
    keys = {
        "schema_version",
        "artifact_type",
        "image_digest",
        "network",
        "client",
        "servers",
        "directional_coverage",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError("controlled network receipt fields are invalid")
    image = value["image_digest"]
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["artifact_type"] != "qcsd-buflo-controlled-network-v1"
        or not isinstance(image, str)
        or not image.startswith("sha256:")
        or len(image) != 71
        or any(character not in "0123456789abcdef" for character in image[7:])
        or not isinstance(value["network"], str)
        or not value["network"]
    ):
        raise ValueError("controlled network receipt identity is invalid")
    expected_coverage = {
        "client_to_server": {
            "shaped_egress": "client:eth0",
            "opposite_ingress": "servers:eth0",
        },
        "server_to_client": {
            "shaped_egress": "servers:eth0",
            "opposite_ingress": "client:eth0",
        },
    }
    if value["directional_coverage"] != expected_coverage:
        raise ValueError("controlled network receipt lacks bilateral directional coverage")
    _validate_legacy_qdisc_endpoint(value["client"], role="client", expected=client_qdisc)
    servers = value["servers"]
    if not isinstance(servers, list) or len(servers) != 2:
        raise ValueError("controlled network receipt requires two server egress observations")
    aliases = []
    for server in servers:
        _validate_legacy_qdisc_endpoint(server, role="server", expected=server_qdisc)
        aliases.append(server.get("alias"))
    if sorted(aliases) != ["qcsd-buflo-server-one", "qcsd-buflo-server-two"]:
        raise ValueError("controlled network server aliases are invalid")


def _validate_legacy_qdisc_endpoint(value: Any, *, role: str, expected: str) -> None:
    required = {"role", "interface", "applied_qdisc", "observed_qdisc"}
    allowed = required | ({"alias"} if role == "server" else set())
    if (
        not isinstance(value, Mapping)
        or set(value) != allowed
        or value["role"] != role
        or value["interface"] != "eth0"
        or value["applied_qdisc"] != expected
        or not isinstance(value["observed_qdisc"], list)
    ):
        raise ValueError(f"controlled {role} qdisc receipt is invalid")
    rows = value["observed_qdisc"]
    netem = [row for row in rows if isinstance(row, Mapping) and row.get("kind") == "netem"]
    if expected == "none":
        if netem:
            raise ValueError(f"controlled {role} clean receipt unexpectedly contains netem")
        return
    if len(netem) != 1 or netem[0].get("root") is not True:
        raise ValueError(f"controlled {role} receipt has no unique root netem qdisc")
    options = netem[0].get("options")
    if not isinstance(options, Mapping):
        raise TypeError(f"controlled {role} netem options are invalid")
    delay = options.get("delay")
    delay_valid = (
        delay in {25_000, "25ms"}
        if not isinstance(delay, Mapping)
        else delay.get("delay") == 0.025
        and delay.get("jitter") in {None, 0}
        and delay.get("correlation") in {None, 0}
    )
    if "delay 25ms" in expected and not delay_valid:
        raise ValueError(f"controlled {role} netem delay differs from 25ms")
    rate = options.get("rate")
    rate_value = rate.get("rate") if isinstance(rate, Mapping) else rate
    if "rate 5mbit" in expected and rate_value not in {625_000, 5_000_000, "5mbit"}:
        raise ValueError(f"controlled {role} netem rate differs from 5mbit")
    if "rate 5mbit" not in expected and rate is not None:
        raise ValueError(f"controlled {role} netem receipt has an unexpected rate")
    if "limit 100" in expected and options.get("limit") != 100:
        raise ValueError(f"controlled {role} netem queue differs from 100 packets")
    loss = options.get("loss-random", options.get("loss"))
    loss_value = loss.get("loss") if isinstance(loss, Mapping) else loss
    if "loss 1%" in expected and loss_value not in {0.01, 1, "1%"}:
        raise ValueError(f"controlled {role} netem loss differs from 1 percent")
    if "loss 1%" not in expected and loss is not None:
        raise ValueError(f"controlled {role} netem receipt has unexpected loss")


_SAFE_OFFLOADS = {
    "gro": False,
    "gso": False,
    "tso": False,
    "tx_udp_segmentation": False,
}
_CONTROLLED_OBSERVATION_CONTRACT = {
    "schema_version": 1,
    "normalization": "qcsd-controlled-network-semantic-observation-v1",
    "commands": [
        "ip -j address show dev <interface>",
        "ip -j -4 route show table main",
        "tc -details -j qdisc show dev <interface>",
        "tc -details -j filter show dev eth0 parent ffff:",
        "ethtool --json --show-features <interface>",
        "cat /proc/sys/net/ipv4/ip_forward",
        "client:/etc/hosts exact server aliases",
    ],
}
_INGRESS_REDIRECT_CONTRACT = {
    "protocol": "all",
    "kind": "u32",
    "match": {"value": "0", "mask": "0", "offset": 0},
    "action": {
        "kind": "mirred",
        "mirred_action": "redirect",
        "direction": "egress",
        "to_device": "ifb0",
        "control_action": "stolen",
    },
}


def _exact_mapping(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"controlled {label} fields are invalid")
    return value


def _controlled_network_pair(
    client_name: str, server_name: str
) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, str]:
    match = re.fullmatch(r"(qcsd-buflo-study-v([1-9][0-9]*))-client", client_name)
    if match is None or server_name != f"{match.group(1)}-server":
        raise ValueError("controlled shared-router network names are invalid")
    cohort = int(match.group(2))
    seed = hashlib.sha256(f"qcsd-buflo-study-v{cohort}".encode()).digest()
    pair = int.from_bytes(seed[:4], "big") % 16_384
    base = int(ipaddress.ip_address("10.128.0.0")) + pair * 512
    return (
        ipaddress.ip_network((base, 24)),
        ipaddress.ip_network((base + 256, 24)),
        match.group(1),
    )


def _canonical_ipam(value: Any, *, expected_name: str) -> dict[str, str]:
    item = _exact_mapping(value, {"name", "ipam"}, "Docker network observation")
    if item["name"] != expected_name:
        raise ValueError("controlled Docker network name differs from its launch binding")
    ipam = item["ipam"]
    if not isinstance(ipam, list) or len(ipam) != 1:
        raise ValueError("controlled Docker network requires one IPv4 IPAM record")
    row = _exact_mapping(ipam[0], {"Subnet", "IPRange", "Gateway"}, "Docker IPv4 IPAM observation")
    if row["IPRange"] != "":
        raise ValueError("controlled Docker network cannot use a secondary IP range")
    try:
        subnet = ipaddress.ip_network(row["Subnet"], strict=True)
        gateway = ipaddress.ip_address(row["Gateway"])
    except (TypeError, ValueError) as error:
        raise ValueError("controlled Docker IPAM observation is invalid") from error
    if not isinstance(subnet, ipaddress.IPv4Network) or gateway != subnet.network_address + 1:
        raise ValueError("controlled Docker IPv4 gateway is not the fixed first host")
    return {"name": expected_name, "subnet": str(subnet), "gateway": str(gateway)}


def _canonical_address(value: Any, interface: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        raise ValueError(f"controlled {interface} address observation is invalid")
    row = value[0]
    flags = row.get("flags")
    if (
        row.get("ifname") != interface
        or row.get("mtu") != 1_500
        or not isinstance(flags, list)
        or "UP" not in flags
        or "LOWER_UP" not in flags
    ):
        raise ValueError(f"controlled {interface} is not an up 1500-byte interface")
    addr_info = row.get("addr_info")
    if not isinstance(addr_info, list):
        raise ValueError(f"controlled {interface} address list is invalid")
    ipv4 = [
        entry for entry in addr_info if isinstance(entry, Mapping) and entry.get("family") == "inet"
    ]
    if len(ipv4) > 1:
        raise ValueError(f"controlled {interface} has multiple IPv4 addresses")
    address: str | None = None
    if ipv4:
        local = ipv4[0].get("local")
        prefix = ipv4[0].get("prefixlen")
        if not isinstance(local, str) or type(prefix) is not int:
            raise ValueError(f"controlled {interface} IPv4 address is invalid")
        try:
            address = str(ipaddress.ip_interface(f"{local}/{prefix}"))
        except ValueError as error:
            raise ValueError(f"controlled {interface} IPv4 address is invalid") from error
    return {"interface": interface, "ipv4": address, "mtu": 1_500, "up": True}


def _duration_seconds(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, str) and value.endswith("ms"):
        return float(value[:-2]) / 1_000
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("controlled netem duration is invalid")
    return float(value) / 1_000_000 if value > 1 else float(value)


def _canonical_netem_options(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("controlled netem options are invalid")
    required = {"limit", "delay", "ecn", "gap"}
    optional = {"rate", "loss-random"}
    if not required <= set(value) or not set(value) <= required | optional:
        raise ValueError("controlled netem options contain unknown or missing fields")
    delay = value.get("delay")
    if isinstance(delay, Mapping):
        if set(delay) != {"delay", "jitter", "correlation"}:
            raise ValueError("controlled netem delay fields are invalid")
        delay_seconds = _duration_seconds(delay.get("delay"))
        jitter_seconds = _duration_seconds(delay.get("jitter"))
        delay_correlation = delay.get("correlation")
    else:
        delay_seconds = _duration_seconds(delay)
        jitter_seconds = None
        delay_correlation = None
    rate = value.get("rate")
    if isinstance(rate, Mapping) and set(rate) != {
        "rate",
        "packetoverhead",
        "cellsize",
        "celloverhead",
    }:
        raise ValueError("controlled netem rate fields are invalid")
    rate_value = rate.get("rate") if isinstance(rate, Mapping) else rate
    packet_overhead = rate.get("packetoverhead") if isinstance(rate, Mapping) else None
    cell_size = rate.get("cellsize") if isinstance(rate, Mapping) else None
    cell_overhead = rate.get("celloverhead") if isinstance(rate, Mapping) else None
    loss = value.get("loss-random")
    if isinstance(loss, Mapping) and set(loss) != {"loss", "correlation"}:
        raise ValueError("controlled netem loss fields are invalid")
    loss_value = loss.get("loss") if isinstance(loss, Mapping) else loss
    loss_correlation = loss.get("correlation") if isinstance(loss, Mapping) else None
    numeric = (
        value.get("limit"),
        jitter_seconds,
        delay_correlation,
        rate_value,
        packet_overhead,
        cell_size,
        cell_overhead,
        loss_value,
        loss_correlation,
        value.get("gap"),
    )
    if any(isinstance(item, bool) for item in numeric if item is not None):
        raise ValueError("controlled netem numeric option is invalid")
    return {
        "limit_packets": value.get("limit"),
        "delay_seconds": delay_seconds,
        "jitter_seconds": jitter_seconds,
        "delay_correlation": delay_correlation,
        "rate_bytes_per_second": rate_value,
        "packet_overhead_bytes": packet_overhead,
        "cell_size_bytes": cell_size,
        "cell_overhead_bytes": cell_overhead,
        "loss_fraction": loss_value,
        "loss_correlation": loss_correlation,
        "gap": value.get("gap"),
        "ecn": value.get("ecn"),
    }


def _canonical_qdiscs(value: Any, interface: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"controlled {interface} qdisc observation is invalid")
    rows: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("kind"), str):
            raise ValueError(f"controlled {interface} qdisc row is invalid")
        kind = raw["kind"]
        rows.append(
            {
                "kind": kind,
                "root": raw.get("root") is True,
                "parent": raw.get("parent") if isinstance(raw.get("parent"), str) else None,
                "netem": _canonical_netem_options(raw.get("options")) if kind == "netem" else None,
            }
        )
    rows.sort(key=lambda row: (row["kind"], str(row["parent"]), not row["root"]))
    return rows


def _canonical_routes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("controlled route observation is invalid")
    rows: list[dict[str, Any]] = []
    for raw in value:
        allowed = {"dst", "gateway", "dev", "flags", "prefsrc", "protocol", "scope"}
        if (
            not isinstance(raw, Mapping)
            or not {"dst", "dev", "flags"} <= set(raw)
            or not set(raw) <= allowed
            or raw["flags"] != []
            or not isinstance(raw.get("dev"), str)
        ):
            raise ValueError("controlled route row is invalid")
        row = {
            "destination": raw.get("dst", "default"),
            "gateway": raw.get("gateway"),
            "device": raw["dev"],
            "preferred_source": raw.get("prefsrc"),
            "protocol": raw.get("protocol"),
            "scope": raw.get("scope"),
        }
        if any(item is not None and not isinstance(item, str) for item in row.values()):
            raise ValueError("controlled route value is invalid")
        rows.append(row)
    rows.sort(key=lambda row: json.dumps(row, sort_keys=True))
    return rows


def _canonical_offloads(value: Any, interface: str) -> dict[str, bool]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        raise ValueError(f"controlled {interface} offload observation is invalid")
    row = value[0]
    if row.get("ifname") != interface:
        raise ValueError(f"controlled {interface} offload interface is invalid")
    fields = {
        "gro": "generic-receive-offload",
        "gso": "generic-segmentation-offload",
        "tso": "tcp-segmentation-offload",
        "tx_udp_segmentation": "tx-udp-segmentation",
    }
    observed: dict[str, bool] = {}
    for short, feature in fields.items():
        state = row.get(feature)
        if not isinstance(state, Mapping) or type(state.get("active")) is not bool:
            raise ValueError(f"controlled {interface} {short} observation is invalid")
        observed[short] = state["active"]
    if observed != _SAFE_OFFLOADS:
        raise ValueError(f"controlled {interface} packet offloads are not disabled")
    return observed


def _canonical_ingress_filter(value: Any) -> dict[str, Any] | None:
    if value == []:
        return None
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError("controlled router ingress filter observation is invalid")
    action_rows = []
    for row in value:
        if not isinstance(row, Mapping) or row.get("protocol") != "all" or row.get("kind") != "u32":
            raise ValueError("controlled router ingress filter is not an all-packet u32 filter")
        options = row.get("options")
        if isinstance(options, Mapping) and options.get("actions") is not None:
            action_rows.append(options)
    if len(action_rows) != 1:
        raise ValueError("controlled router ingress filter lacks one terminal redirect")
    options = action_rows[0]
    match = options.get("match")
    actions = options.get("actions")
    if (
        not isinstance(match, Mapping)
        or str(match.get("value")) != "0"
        or str(match.get("mask")) != "0"
        or match.get("off") != 0
        or not isinstance(actions, list)
        or len(actions) != 1
        or not isinstance(actions[0], Mapping)
    ):
        raise ValueError("controlled router ingress filter match is not catch-all")
    action = actions[0]
    control = action.get("control_action")
    if (
        action.get("kind") != "mirred"
        or action.get("mirred_action") != "redirect"
        or action.get("direction") != "egress"
        or action.get("to_dev") != "ifb0"
        or not isinstance(control, Mapping)
        or control.get("type") != "stolen"
    ):
        raise ValueError("controlled router ingress filter does not redirect to ifb0")
    return deepcopy(_INGRESS_REDIRECT_CONTRACT)


def _observe_json(command: Sequence[str], label: str) -> Any:
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"cannot observe controlled {label}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"controlled {label} observation is not JSON") from error


def _observe_client_namespace() -> dict[str, Any]:
    hosts: dict[str, list[str]] = {
        "qcsd-buflo-server-one": [],
        "qcsd-buflo-server-two": [],
    }
    for line in Path("/etc/hosts").read_text(encoding="utf-8").splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        for alias in hosts:
            if alias in fields[1:]:
                hosts[alias].append(fields[0])
    return {
        "addresses": {
            "eth0": _observe_json(["ip", "-j", "address", "show", "dev", "eth0"], "client address")
        },
        "qdiscs": {
            "eth0": _observe_json(
                ["tc", "-details", "-j", "qdisc", "show", "dev", "eth0"], "client qdisc"
            )
        },
        "offloads": {
            "eth0": _observe_json(
                ["ethtool", "--json", "--show-features", "eth0"], "client offloads"
            )
        },
        "routes": _observe_json(
            ["ip", "-j", "-4", "route", "show", "table", "main"], "client routes"
        ),
        "hosts": hosts,
    }


def _decode_controlled_network_evidence(value: str) -> Mapping[str, Any]:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(
            "controlled shared-router evidence is not canonical base64 JSON"
        ) from error
    return _exact_mapping(
        parsed,
        {"schema_version", "client_network", "server_network", "router", "servers"},
        "shared-router launch evidence",
    )


def _address_ip(address: Mapping[str, Any], label: str) -> ipaddress.IPv4Address:
    value = address.get("ipv4")
    if not isinstance(value, str):
        raise ValueError(f"controlled {label} has no IPv4 address")
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError as error:
        raise ValueError(f"controlled {label} IPv4 address is invalid") from error
    if not isinstance(interface, ipaddress.IPv4Interface):
        raise ValueError(f"controlled {label} must use IPv4")
    return interface.ip


def _route(
    destination: str,
    *,
    device: str,
    gateway: str | None = None,
    preferred_source: str | None = None,
    protocol: str | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    return {
        "destination": destination,
        "gateway": gateway,
        "device": device,
        "preferred_source": preferred_source,
        "protocol": protocol,
        "scope": scope,
    }


def _sorted_routes(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))


def _expected_namespace_routes(
    *,
    own_subnet: str,
    own_gateway: str,
    own_ip: str,
    remote_subnet: str,
    remote_router_ip: str,
    device: str,
) -> list[dict[str, Any]]:
    return _sorted_routes(
        [
            _route("default", device=device, gateway=own_gateway),
            _route(
                own_subnet,
                device=device,
                preferred_source=own_ip,
                protocol="kernel",
                scope="link",
            ),
            _route(remote_subnet, device=device, gateway=remote_router_ip),
        ]
    )


def _netem_contract(expected: str) -> dict[str, Any] | None:
    if expected == "none":
        return None
    return {
        "limit_packets": 100 if "limit 100" in expected else 1_000,
        "delay_seconds": 0.025,
        "jitter_seconds": 0.0,
        "delay_correlation": 0,
        "rate_bytes_per_second": 625_000 if "rate 5mbit" in expected else None,
        "packet_overhead_bytes": 0 if "rate 5mbit" in expected else None,
        "cell_size_bytes": 0 if "rate 5mbit" in expected else None,
        "cell_overhead_bytes": 0 if "rate 5mbit" in expected else None,
        "loss_fraction": 0.01 if "loss 1%" in expected else None,
        "loss_correlation": 0 if "loss 1%" in expected else None,
        "gap": 0,
        "ecn": False,
    }


def _baseline_qdisc(kind: str) -> list[dict[str, Any]]:
    return [{"kind": kind, "root": True, "parent": None, "netem": None}]


def _shaped_qdisc(expected: str, *, with_ingress: bool = False) -> list[dict[str, Any]]:
    contract = _netem_contract(expected)
    if contract is None:
        raise ValueError("internal shaped qdisc requires an impairment")
    rows = [{"kind": "netem", "root": True, "parent": None, "netem": contract}]
    if with_ingress:
        rows.append({"kind": "ingress", "root": False, "parent": "ffff:fff1", "netem": None})
    return sorted(rows, key=lambda row: (row["kind"], str(row["parent"]), not row["root"]))


def _build_shared_router_network_receipt(
    *,
    network: str,
    controlled_network_evidence_b64: str,
    client_qdisc: str,
    server_qdisc: str,
    cohort_version: int,
) -> dict[str, Any]:
    if type(cohort_version) is not int or cohort_version <= 0:
        raise ValueError("controlled shared-router cohort version is invalid")
    if network != f"qcsd-buflo-study-v{cohort_version}-client":
        raise ValueError("controlled shared-router network differs from the requested cohort")
    evidence = _decode_controlled_network_evidence(controlled_network_evidence_b64)
    if evidence["schema_version"] != SCHEMA_VERSION:
        raise ValueError("controlled shared-router launch evidence schema is invalid")
    server_network_name = network.removesuffix("-client") + "-server"
    client_network = _canonical_ipam(evidence["client_network"], expected_name=network)
    server_network = _canonical_ipam(evidence["server_network"], expected_name=server_network_name)
    expected_client_subnet, expected_server_subnet, base_name = _controlled_network_pair(
        client_network["name"], server_network["name"]
    )
    if client_network["subnet"] != str(expected_client_subnet) or server_network["subnet"] != str(
        expected_server_subnet
    ):
        raise ValueError("controlled Docker subnets differ from the fixed cohort allocation")

    router = _exact_mapping(
        evidence["router"],
        {
            "container",
            "addresses",
            "qdiscs",
            "offloads",
            "routes",
            "client_ingress_filters",
            "ip_forward",
        },
        "router namespace observation",
    )
    if router["container"] != f"{base_name}-router" or router["ip_forward"] != 1:
        raise ValueError("controlled router identity or IPv4 forwarding state is invalid")
    router_addresses_raw = _exact_mapping(
        router["addresses"], {"eth0", "eth1", "ifb0"}, "router address observations"
    )
    router_qdiscs_raw = _exact_mapping(
        router["qdiscs"], {"eth0", "eth1", "ifb0"}, "router qdisc observations"
    )
    router_offloads_raw = _exact_mapping(
        router["offloads"], {"eth0", "eth1"}, "router offload observations"
    )
    router_addresses = {
        interface: _canonical_address(router_addresses_raw[interface], interface)
        for interface in ("eth0", "eth1", "ifb0")
    }
    router_qdiscs = {
        interface: _canonical_qdiscs(router_qdiscs_raw[interface], interface)
        for interface in ("eth0", "eth1", "ifb0")
    }
    router_offloads = {
        interface: _canonical_offloads(router_offloads_raw[interface], interface)
        for interface in ("eth0", "eth1")
    }
    router_client_ip = _address_ip(router_addresses["eth0"], "router eth0")
    router_server_ip = _address_ip(router_addresses["eth1"], "router eth1")
    if (
        router_client_ip not in expected_client_subnet
        or router_server_ip not in expected_server_subnet
        or router_addresses["ifb0"]["ipv4"] is not None
    ):
        raise ValueError("controlled router interface-to-network binding is invalid")

    raw_servers = evidence["servers"]
    if not isinstance(raw_servers, list) or len(raw_servers) != 2:
        raise ValueError("controlled shared router requires two ordinary servers")
    servers: list[dict[str, Any]] = []
    for rank, raw_server in enumerate(raw_servers, start=1):
        server = _exact_mapping(
            raw_server,
            {"container", "alias", "addresses", "qdiscs", "offloads", "routes"},
            "ordinary server namespace observation",
        )
        suffix = "one" if rank == 1 else "two"
        alias = f"qcsd-buflo-server-{suffix}"
        if server["alias"] != alias or server["container"] != f"{base_name}-server-{suffix}":
            raise ValueError("controlled ordinary server identity is invalid")
        addresses = _exact_mapping(server["addresses"], {"eth0"}, "server addresses")
        qdiscs = _exact_mapping(server["qdiscs"], {"eth0"}, "server qdiscs")
        offloads = _exact_mapping(server["offloads"], {"eth0"}, "server offloads")
        address = _canonical_address(addresses["eth0"], "eth0")
        server_ip = _address_ip(address, alias)
        if server_ip not in expected_server_subnet:
            raise ValueError("controlled ordinary server is outside the server network")
        servers.append(
            {
                "role": "ordinary-http3-server-no-defense",
                "alias": alias,
                "container": server["container"],
                "interface": "eth0",
                "ipv4": str(server_ip),
                "observed_address": address,
                "observed_routes": _canonical_routes(server["routes"]),
                "observed_qdiscs": _canonical_qdiscs(qdiscs["eth0"], "eth0"),
                "observed_offloads": _canonical_offloads(offloads["eth0"], "eth0"),
            }
        )
    if servers[0]["ipv4"] == servers[1]["ipv4"]:
        raise ValueError("controlled ordinary servers share an IPv4 address")

    client_raw = _observe_client_namespace()
    client_address = _canonical_address(client_raw["addresses"]["eth0"], "eth0")
    client_ip = _address_ip(client_address, "client eth0")
    if client_ip not in expected_client_subnet:
        raise ValueError("controlled client is outside the client network")
    hosts = client_raw["hosts"]
    expected_hosts = {server["alias"]: [server["ipv4"]] for server in servers}
    if hosts != expected_hosts:
        raise ValueError("controlled client does not have exact cross-network server host bindings")

    receipt = {
        "schema_version": CONTROLLED_NETWORK_RECEIPT_SCHEMA_VERSION,
        "artifact_type": "qcsd-buflo-controlled-network-v2",
        "image_digest": _controlled_image_digest(),
        "topology": {
            "kind": "shared-two-network-router",
            "client_network": client_network,
            "server_network": server_network,
            "router_interfaces": {
                "client_facing": "eth0",
                "server_facing": "eth1",
                "client_ingress_ifb": "ifb0",
            },
        },
        "capture_point": {
            "endpoint": "client:eth0",
            "client_to_server_position": "before-router-eth0-ingress-ifb0-netem",
            "server_to_client_position": "after-router-eth0-root-netem",
            "endpoint_impairment_qdiscs": 0,
        },
        "client": {
            "role": "capture-and-client",
            "interface": "eth0",
            "network": client_network["name"],
            "ipv4": str(client_ip),
            "observed_address": client_address,
            "observed_routes": _canonical_routes(client_raw["routes"]),
            "observed_qdiscs": _canonical_qdiscs(client_raw["qdiscs"]["eth0"], "eth0"),
            "observed_offloads": _canonical_offloads(client_raw["offloads"]["eth0"], "eth0"),
            "observed_hosts": hosts,
        },
        "router": {
            "role": "shared-impairment-router",
            "container": router["container"],
            "client_ipv4": str(router_client_ip),
            "server_ipv4": str(router_server_ip),
            "ip_forward": router["ip_forward"],
            "observed_addresses": router_addresses,
            "observed_routes": _canonical_routes(router["routes"]),
            "observed_qdiscs": router_qdiscs,
            "observed_client_ingress_filter": _canonical_ingress_filter(
                router["client_ingress_filters"]
            ),
            "observed_offloads": router_offloads,
        },
        "servers": servers,
        "directional_coverage": {
            "client_to_server": {
                "shaping_site": "router:eth0-ingress-redirect-ifb0-root",
                "applied_qdisc": client_qdisc,
                "impairment_applications": 0 if client_qdisc == "none" else 1,
                "capture_position": "before-impairment",
            },
            "server_to_client": {
                "shaping_site": "router:eth0-root-egress",
                "applied_qdisc": server_qdisc,
                "impairment_applications": 0 if server_qdisc == "none" else 1,
                "capture_position": "after-impairment",
            },
        },
        "rate_aggregation": {
            "scope": "one-shared-qdisc-per-direction-across-both-server-origins",
            "client_to_server": "router:ifb0-root",
            "server_to_client": "router:eth0-root",
        },
        "observation_contract": deepcopy(_CONTROLLED_OBSERVATION_CONTRACT),
    }
    _validate_shared_router_network_receipt(
        receipt,
        client_qdisc=client_qdisc,
        server_qdisc=server_qdisc,
        cohort_version=cohort_version,
    )
    return receipt


def _with_kernel_tx_network_receipt(
    network_receipt: Mapping[str, Any],
    operation: Callable[..., Any],
    /,
    *arguments: Any,
) -> Any:
    """Expose one validated controlled-network receipt only while collecting.

    The environment seam is intentionally narrow: the orchestrator and the
    direct timing-stress collector ultimately converge on ``_collect_attempt``,
    while the immutable campaign receipt remains the source of the canonical
    network value.  Restoring the prior process environment prevents a later
    public capture from inheriting a controlled observer assertion.
    """

    encoded = base64.b64encode(
        json.dumps(
            dict(network_receipt),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    previous = os.environ.get(KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV)
    os.environ[KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV] = encoded
    try:
        return operation(*arguments)
    finally:
        if previous is None:
            os.environ.pop(KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV, None)
        else:
            os.environ[KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV] = previous


def _validate_shared_router_network_receipt(
    value: Any, *, client_qdisc: str, server_qdisc: str, cohort_version: int | None
) -> None:
    if type(cohort_version) is not int or cohort_version <= 0:
        raise ValueError("controlled shared-router cohort version is invalid")
    receipt = _exact_mapping(
        value,
        {
            "schema_version",
            "artifact_type",
            "image_digest",
            "topology",
            "capture_point",
            "client",
            "router",
            "servers",
            "directional_coverage",
            "rate_aggregation",
            "observation_contract",
        },
        "shared-router network receipt",
    )
    image = receipt["image_digest"]
    if (
        receipt["schema_version"] != CONTROLLED_NETWORK_RECEIPT_SCHEMA_VERSION
        or receipt["artifact_type"] != "qcsd-buflo-controlled-network-v2"
        or not isinstance(image, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None
    ):
        raise ValueError("controlled shared-router network receipt identity is invalid")
    topology = _exact_mapping(
        receipt["topology"],
        {"kind", "client_network", "server_network", "router_interfaces"},
        "shared-router topology",
    )
    if topology["kind"] != "shared-two-network-router":
        raise ValueError("controlled network does not use one shared two-network router")
    client_network = _exact_mapping(
        topology["client_network"], {"name", "subnet", "gateway"}, "client network"
    )
    server_network = _exact_mapping(
        topology["server_network"], {"name", "subnet", "gateway"}, "server network"
    )
    expected_client_subnet, expected_server_subnet, base_name = _controlled_network_pair(
        client_network["name"], server_network["name"]
    )
    if base_name != f"qcsd-buflo-study-v{cohort_version}":
        raise ValueError("controlled shared-router receipt differs from the campaign cohort")
    if (
        client_network
        != {
            "name": f"{base_name}-client",
            "subnet": str(expected_client_subnet),
            "gateway": str(expected_client_subnet.network_address + 1),
        }
        or server_network
        != {
            "name": f"{base_name}-server",
            "subnet": str(expected_server_subnet),
            "gateway": str(expected_server_subnet.network_address + 1),
        }
        or topology["router_interfaces"]
        != {"client_facing": "eth0", "server_facing": "eth1", "client_ingress_ifb": "ifb0"}
    ):
        raise ValueError("controlled shared-router topology/IPAM binding is invalid")
    if receipt["capture_point"] != {
        "endpoint": "client:eth0",
        "client_to_server_position": "before-router-eth0-ingress-ifb0-netem",
        "server_to_client_position": "after-router-eth0-root-netem",
        "endpoint_impairment_qdiscs": 0,
    }:
        raise ValueError("controlled client capture point is not outside both impairments")

    client = _exact_mapping(
        receipt["client"],
        {
            "role",
            "interface",
            "network",
            "ipv4",
            "observed_address",
            "observed_routes",
            "observed_qdiscs",
            "observed_offloads",
            "observed_hosts",
        },
        "client namespace receipt",
    )
    try:
        client_ip = ipaddress.ip_address(client["ipv4"])
    except (TypeError, ValueError) as error:
        raise ValueError("controlled client IPv4 receipt is invalid") from error
    if (
        client["role"] != "capture-and-client"
        or client["interface"] != "eth0"
        or client["network"] != client_network["name"]
        or client_ip not in expected_client_subnet
        or client["observed_address"]
        != {"interface": "eth0", "ipv4": f"{client_ip}/24", "mtu": 1_500, "up": True}
        or client["observed_qdiscs"] != _baseline_qdisc("noqueue")
        or client["observed_offloads"] != _SAFE_OFFLOADS
    ):
        raise ValueError("controlled client address/qdisc/offload receipt is invalid")

    router = _exact_mapping(
        receipt["router"],
        {
            "role",
            "container",
            "client_ipv4",
            "server_ipv4",
            "ip_forward",
            "observed_addresses",
            "observed_routes",
            "observed_qdiscs",
            "observed_client_ingress_filter",
            "observed_offloads",
        },
        "router namespace receipt",
    )
    try:
        router_client_ip = ipaddress.ip_address(router["client_ipv4"])
        router_server_ip = ipaddress.ip_address(router["server_ipv4"])
    except (TypeError, ValueError) as error:
        raise ValueError("controlled router IPv4 receipt is invalid") from error
    if (
        router["role"] != "shared-impairment-router"
        or router["container"] != f"{base_name}-router"
        or router["ip_forward"] != 1
        or router_client_ip not in expected_client_subnet
        or router_server_ip not in expected_server_subnet
        or router["observed_offloads"] != {"eth0": _SAFE_OFFLOADS, "eth1": _SAFE_OFFLOADS}
    ):
        raise ValueError("controlled router identity/forwarding/offload receipt is invalid")
    expected_router_addresses = {
        "eth0": {"interface": "eth0", "ipv4": f"{router_client_ip}/24", "mtu": 1_500, "up": True},
        "eth1": {"interface": "eth1", "ipv4": f"{router_server_ip}/24", "mtu": 1_500, "up": True},
        "ifb0": {"interface": "ifb0", "ipv4": None, "mtu": 1_500, "up": True},
    }
    if router["observed_addresses"] != expected_router_addresses:
        raise ValueError("controlled router eth0/eth1/ifb0 address binding is invalid")

    raw_servers = receipt["servers"]
    if not isinstance(raw_servers, list) or len(raw_servers) != 2:
        raise ValueError("controlled shared-router receipt requires two ordinary servers")
    server_ips: list[ipaddress.IPv4Address] = []
    expected_servers: list[Mapping[str, Any]] = []
    for rank, server_value in enumerate(raw_servers, start=1):
        server = _exact_mapping(
            server_value,
            {
                "role",
                "alias",
                "container",
                "interface",
                "ipv4",
                "observed_address",
                "observed_routes",
                "observed_qdiscs",
                "observed_offloads",
            },
            "ordinary server receipt",
        )
        suffix = "one" if rank == 1 else "two"
        alias = f"qcsd-buflo-server-{suffix}"
        try:
            server_ip = ipaddress.ip_address(server["ipv4"])
        except (TypeError, ValueError) as error:
            raise ValueError("controlled server IPv4 receipt is invalid") from error
        if (
            server["role"] != "ordinary-http3-server-no-defense"
            or server["alias"] != alias
            or server["container"] != f"{base_name}-server-{suffix}"
            or server["interface"] != "eth0"
            or server_ip not in expected_server_subnet
            or server["observed_address"]
            != {"interface": "eth0", "ipv4": f"{server_ip}/24", "mtu": 1_500, "up": True}
            or server["observed_qdiscs"] != _baseline_qdisc("noqueue")
            or server["observed_offloads"] != _SAFE_OFFLOADS
        ):
            raise ValueError("controlled ordinary server namespace receipt is invalid")
        server_ips.append(server_ip)
        expected_servers.append(server)
    if len(set(server_ips)) != 2:
        raise ValueError("controlled ordinary server IPv4 identities are not distinct")

    expected_client_routes = _expected_namespace_routes(
        own_subnet=str(expected_client_subnet),
        own_gateway=client_network["gateway"],
        own_ip=str(client_ip),
        remote_subnet=str(expected_server_subnet),
        remote_router_ip=str(router_client_ip),
        device="eth0",
    )
    if client["observed_routes"] != expected_client_routes:
        raise ValueError("controlled client route bypasses or does not bind the shared router")
    expected_hosts = {
        "qcsd-buflo-server-one": [str(server_ips[0])],
        "qcsd-buflo-server-two": [str(server_ips[1])],
    }
    if client["observed_hosts"] != expected_hosts:
        raise ValueError("controlled client cross-network host bindings are invalid")
    expected_router_routes = _sorted_routes(
        [
            _route("default", device="eth0", gateway=client_network["gateway"]),
            _route(
                str(expected_client_subnet),
                device="eth0",
                preferred_source=str(router_client_ip),
                protocol="kernel",
                scope="link",
            ),
            _route(
                str(expected_server_subnet),
                device="eth1",
                preferred_source=str(router_server_ip),
                protocol="kernel",
                scope="link",
            ),
        ]
    )
    if router["observed_routes"] != expected_router_routes:
        raise ValueError("controlled router routes do not exactly join the two networks")
    for server, server_ip in zip(expected_servers, server_ips, strict=True):
        expected_routes = _expected_namespace_routes(
            own_subnet=str(expected_server_subnet),
            own_gateway=server_network["gateway"],
            own_ip=str(server_ip),
            remote_subnet=str(expected_client_subnet),
            remote_router_ip=str(router_server_ip),
            device="eth0",
        )
        if server["observed_routes"] != expected_routes:
            raise ValueError("controlled ordinary server route bypasses the shared router")

    impaired = client_qdisc != "none"
    expected_router_qdiscs = {
        "eth0": _shaped_qdisc(server_qdisc, with_ingress=True)
        if impaired
        else _baseline_qdisc("noqueue"),
        "eth1": _baseline_qdisc("noqueue"),
        "ifb0": _shaped_qdisc(client_qdisc) if impaired else _baseline_qdisc("fq_codel"),
    }
    if router["observed_qdiscs"] != expected_router_qdiscs:
        raise ValueError("controlled router qdisc placement or parameters are invalid")
    if router["observed_client_ingress_filter"] != (
        _INGRESS_REDIRECT_CONTRACT if impaired else None
    ):
        raise ValueError("controlled router ingress redirect evidence is invalid")
    expected_coverage = {
        "client_to_server": {
            "shaping_site": "router:eth0-ingress-redirect-ifb0-root",
            "applied_qdisc": client_qdisc,
            "impairment_applications": 1 if impaired else 0,
            "capture_position": "before-impairment",
        },
        "server_to_client": {
            "shaping_site": "router:eth0-root-egress",
            "applied_qdisc": server_qdisc,
            "impairment_applications": 1 if impaired else 0,
            "capture_position": "after-impairment",
        },
    }
    if receipt["directional_coverage"] != expected_coverage:
        raise ValueError("controlled router lacks exact once-per-direction impairment coverage")
    if receipt["rate_aggregation"] != {
        "scope": "one-shared-qdisc-per-direction-across-both-server-origins",
        "client_to_server": "router:ifb0-root",
        "server_to_client": "router:eth0-root",
    }:
        raise ValueError("controlled 5mbit profile is not shared across both origins")
    if receipt["observation_contract"] != _CONTROLLED_OBSERVATION_CONTRACT:
        raise ValueError("controlled network observation normalization contract is invalid")


def execute_local_controlled_profile(
    destination: Path,
    *,
    netem_profile: str,
    network: str,
    controlled_network_evidence_b64: str,
    cohort_version: int,
) -> Path:
    """Qualify local chaff and execute/resume one real 40-cell netem campaign."""

    plan = load_study_plan()
    profiles = plan["controlled"]["netem_profiles"]
    matches = [
        (rank, profile) for rank, profile in enumerate(profiles) if profile["id"] == netem_profile
    ]
    if len(matches) != 1:
        raise ValueError("local controlled capture selected an unknown netem profile")
    netem_rank, profile = matches[0]
    destination = destination.resolve()
    if destination.is_symlink():
        raise ValueError("local controlled destination cannot be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    if not destination.is_dir():
        raise ValueError("local controlled destination is not a directory")

    network_receipt = _build_shared_router_network_receipt(
        network=network,
        controlled_network_evidence_b64=controlled_network_evidence_b64,
        client_qdisc=profile["client_qdisc"],
        server_qdisc=profile["server_qdisc"],
        cohort_version=cohort_version,
    )
    receipt = {
        "schema_version": LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        "stage": "controlled",
        "netem_profile": profile["id"],
        "netem_rank": netem_rank,
        "client_qdisc": profile["client_qdisc"],
        "server_qdisc": profile["server_qdisc"],
        "workload_aliases": {
            "local-large": "local-large",
            "local-small": "local-small",
        },
        "fixture_scope": "controlled-live-manifests-including-two-origin-local-large",
        "cohort_version": cohort_version,
        "treatment_order": list(STAGE_TREATMENTS["smoke"]),
        "evidence_class": "controlled-test-only-nonformal",
        "network": network_receipt,
    }
    validate_controlled_campaign_receipt(receipt)

    config = destination / "config"
    campaigns = config / "campaigns"
    workloads = config / "workloads"
    qualifications = config / "chaff-response-qualification-store/v2"
    for directory in (campaigns, workloads, qualifications, destination / "results"):
        if directory.is_symlink():
            raise ValueError(f"local controlled path cannot be a symlink: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
    _create_local_workloads(workloads)
    if netem_rank == 0:
        _qualify_local_workloads(workloads, qualifications)
    elif any(not (qualifications / f"{name}.json").is_file() for name in workloads_ids()):
        raise ValueError(
            "local sustained chaff qualification is missing; execute the clean profile first"
        )

    campaign_path = campaigns / f"buflo-study-v1-controlled-{netem_rank:02d}.yml"
    document = _local_controlled_campaign_document(campaign_path, receipt)
    encoded = yaml.safe_dump(document, sort_keys=False).encode()
    _create_or_verify_bytes(campaign_path, encoded, "local controlled campaign")

    from .orchestrator import CampaignIncomplete, resume_campaign, run_campaign
    from .verification import verify_result

    state_path = destination / "controlled-results.json"
    state = _load_local_state(state_path)
    existing = state["profiles"].get(netem_profile)
    result: Path
    if existing is not None:
        result = Path(existing).resolve()
        if not result.is_relative_to(destination):
            raise ValueError("local controlled checkpoint result escapes its destination")
        try:
            verified = verify_result(result)
        except (OSError, ValueError):
            result = _with_kernel_tx_network_receipt(network_receipt, resume_campaign, result)
        else:
            if verified.experiment["status"] != "complete":
                result = _with_kernel_tx_network_receipt(network_receipt, resume_campaign, result)
    else:
        candidates = sorted(
            (destination / "results" / document["name"]).glob("*"),
            key=lambda path: path.name,
        )
        if len(candidates) > 1:
            raise ValueError("local controlled resume found multiple unbound result roots")
        if candidates:
            result = _with_kernel_tx_network_receipt(
                network_receipt, resume_campaign, candidates[0]
            )
        else:
            try:
                result = _with_kernel_tx_network_receipt(
                    network_receipt,
                    run_campaign,
                    campaign_path,
                    destination / "results",
                )
            except CampaignIncomplete as error:
                result = error.root
                state["profiles"][netem_profile] = str(result)
                atomic_json(state_path, state)
                raise
        state["profiles"][netem_profile] = str(result)
        atomic_json(state_path, state)
    verified = verify_result(result)
    if verified.experiment["status"] != "complete" or len(verified.accepted_samples) != 40:
        raise ValueError("local controlled profile did not produce exactly 40 eligible samples")
    return result


def execute_local_regression(
    destination: Path,
    *,
    network: str,
    controlled_network_evidence_b64: str,
    cohort_version: int,
) -> tuple[Path, ...]:
    """Execute/resume the exact 18-sample nine-mode clean-network regression."""

    destination = destination.resolve()
    if destination.is_symlink():
        raise ValueError("local regression destination cannot be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    clean = {"id": "clean", "client_qdisc": "none", "server_qdisc": "none"}
    network_receipt = _build_shared_router_network_receipt(
        network=network,
        controlled_network_evidence_b64=controlled_network_evidence_b64,
        client_qdisc=clean["client_qdisc"],
        server_qdisc=clean["server_qdisc"],
        cohort_version=cohort_version,
    )
    timing_stress_receipt = execute_buflo_timing_stress(
        destination,
        network_receipt=network_receipt,
        cohort_version=cohort_version,
    )
    receipt = {
        "schema_version": TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION,
        "stage": "regression",
        "netem_profile": clean["id"],
        "netem_rank": 0,
        "client_qdisc": clean["client_qdisc"],
        "server_qdisc": clean["server_qdisc"],
        "workload_aliases": {"complex": "local-large", "simple": "local-small"},
        "fixture_scope": (
            "single-origin-prefix-regression-plus-bound-two-origin-nine-mode-compatibility"
        ),
        "cohort_version": cohort_version,
        "treatment_order": list(load_study_plan()["regression"]["treatments"]),
        "evidence_class": "controlled-test-only-nonformal",
        "network": network_receipt,
        "timing_stress": _file_binding(timing_stress_receipt),
    }
    validate_controlled_campaign_receipt(receipt)

    config = destination / "config"
    campaigns = config / "campaigns"
    workloads = config / "workloads"
    response_qualifications = config / "chaff-response-qualification-store/v2"
    full_qualifications = config / "chaff-qualification-store/v2"
    prefix_specs = config / "chaff-prefix-specs/v2"
    generated_parameters = config / "defense-params"
    for directory in (
        campaigns,
        workloads,
        response_qualifications,
        full_qualifications,
        prefix_specs,
        generated_parameters,
        destination / "results",
    ):
        if directory.is_symlink():
            raise ValueError(f"local regression path cannot be a symlink: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
    _create_regression_workloads(workloads)
    _qualify_local_workloads_named(("simple", "complex"), workloads, response_qualifications)
    _qualify_local_full_chaff(
        workloads,
        full_qualifications,
        prefix_specs,
    )
    walkie_talkie = _write_regression_walkie_talkie(
        workloads,
        full_qualifications,
        prefix_specs,
        generated_parameters,
    )
    documents = _local_regression_campaign_documents(
        campaigns,
        receipt,
        walkie_talkie,
    )
    campaign_paths: list[Path] = []
    for filename, document in documents:
        path = campaigns / filename
        _create_or_verify_bytes(
            path,
            yaml.safe_dump(document, sort_keys=False).encode(),
            "local regression campaign",
        )
        campaign_paths.append(path)
    results = _run_local_campaign_set(
        campaign_paths,
        destination,
        state_name="regression-results.json",
        network_receipt=network_receipt,
    )
    from .verification import verify_result

    counts = [len(verify_result(result).accepted_samples) for result in results]
    if counts != [14, 2, 2] or sum(counts) != 18:
        raise ValueError("local regression did not produce the exact 14+2+2 sample split")
    _execute_regression_multi_origin_compatibility(
        destination,
        results,
        regression_receipt=receipt,
        walkie_talkie=walkie_talkie,
        workload_root=workloads,
        qualification_root=full_qualifications,
        prefix_root=prefix_specs,
    )
    validate_regression_results(results)
    return results


def workloads_ids() -> tuple[str, str]:
    return ("local-small", "local-large")


def _observed_qdisc() -> list[Any]:
    completed = subprocess.run(
        ["tc", "-details", "-j", "qdisc", "show", "dev", "eth0"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"cannot observe client eth0 qdisc: {completed.stderr.strip()}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("client qdisc observation is not JSON") from error
    if not isinstance(value, list):
        raise TypeError("client qdisc observation is not an array")
    return value


def _decode_qdisc(value: str) -> list[Any]:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("server qdisc observation is not canonical base64 JSON") from error
    if not isinstance(parsed, list):
        raise TypeError("server qdisc observation is not an array")
    return parsed


def _controlled_image_digest() -> str:
    value = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "")
    if (
        not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError("controlled capture requires a concrete collection image digest")
    return value


def _create_local_workloads(root: Path) -> None:
    manifests = {
        "local-small": _local_prepared_manifest(
            [
                _local_resource(
                    0,
                    "https://qcsd-buflo-server-one:4433/131072",
                    "Document",
                    131_072,
                ),
                _controlled_csbuflo_rate_driver(1, "local-small"),
            ]
        ),
        "local-large": _local_prepared_manifest(
            [
                _local_resource(
                    0,
                    "https://qcsd-buflo-server-one:4433/131072",
                    "Document",
                    131_072,
                ),
                _local_resource(
                    1,
                    "https://qcsd-buflo-server-one:4433/1024",
                    "Script",
                    1_024,
                    depends_on=[0],
                ),
                _local_resource(
                    2,
                    "https://qcsd-buflo-server-two:4434/4096",
                    "Script",
                    4_096,
                    depends_on=[0],
                ),
                _local_resource(
                    3,
                    "https://qcsd-buflo-server-two:4434/2048",
                    "Image",
                    2_048,
                    depends_on=[2],
                ),
                _controlled_csbuflo_rate_driver(4, "local-large"),
            ]
        ),
    }
    _prepare_local_workloads(
        root,
        manifests,
        label="local controlled workload",
        require_csbuflo_rate_driver=True,
    )


def _create_regression_workloads(root: Path) -> None:
    manifests = {
        "simple": _local_prepared_manifest(
            [
                _local_resource(
                    0,
                    "https://qcsd-buflo-server-one:4433/131072",
                    "Document",
                    131_072,
                )
            ]
        ),
        # The Walkie-Talkie prefix qualifier proves one concrete HTTP/3
        # connection.  This is deliberately the single-origin parameter
        # surrogate; the separately receipted nine-mode compatibility workload
        # below changes only the secondary resource origins and must pass live
        # two-endpoint correctness and fidelity in every mode.
        "complex": _local_prepared_manifest(
            [
                _local_resource(
                    0,
                    "https://qcsd-buflo-server-one:4433/131072",
                    "Document",
                    131_072,
                ),
                _local_resource(
                    1,
                    "https://qcsd-buflo-server-one:4433/1024",
                    "Script",
                    1_024,
                    depends_on=[0],
                ),
                _local_resource(
                    2,
                    "https://qcsd-buflo-server-one:4433/4096",
                    "Script",
                    4_096,
                    depends_on=[0],
                ),
                _local_resource(
                    3,
                    "https://qcsd-buflo-server-one:4433/2048",
                    "Image",
                    2_048,
                    depends_on=[2],
                ),
            ]
        ),
    }
    _prepare_local_workloads(root, manifests, label="local regression workload")


def _create_regression_multi_origin_workload(root: Path) -> None:
    """Prepare the exact two-origin counterpart of the complex WT surrogate."""

    manifests = {
        "complex": _local_prepared_manifest(
            [
                _local_resource(
                    0,
                    "https://qcsd-buflo-server-one:4433/131072",
                    "Document",
                    131_072,
                ),
                _local_resource(
                    1,
                    "https://qcsd-buflo-server-one:4433/1024",
                    "Script",
                    1_024,
                    depends_on=[0],
                ),
                _local_resource(
                    2,
                    "https://qcsd-buflo-server-two:4434/4096",
                    "Script",
                    4_096,
                    depends_on=[0],
                ),
                _local_resource(
                    3,
                    "https://qcsd-buflo-server-two:4434/2048",
                    "Image",
                    2_048,
                    depends_on=[2],
                ),
            ]
        )
    }
    _prepare_local_workloads(
        root,
        manifests,
        label="local regression multi-origin compatibility workload",
    )


def _prepare_local_workloads(
    root: Path,
    manifests: Mapping[str, dict[str, Any]],
    *,
    label: str,
    require_csbuflo_rate_driver: bool = False,
) -> None:
    """Freeze three real local Neqo probes before any qualification/capture.

    The fixed local servers make browser discovery unnecessary, but response
    identities, request headers, UDP ceilings, and source provenance still
    come from actual client executions.  No synthetic preparation receipt is
    admitted.
    """

    from .manifest import (
        canonical_bytes,
        https_origin,
        project_stable_response_lengths,
        validate_manifest,
    )
    from .prepare import (
        PreparationError,
        _freeze_request_headers,
        _neqo_provenance,
        _probe_response_stability,
    )

    for workload_id, unresolved in manifests.items():
        if require_csbuflo_rate_driver:
            _validate_controlled_csbuflo_rate_driver(workload_id, unresolved["resources"])
        destination = root / f"{workload_id}.json"
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                raise ValueError(f"{label} path is not a regular file: {destination}")
            existing = load_json(destination)
            validate_manifest(existing)
            if require_csbuflo_rate_driver:
                _validate_controlled_csbuflo_rate_driver(workload_id, existing["resources"])
            continue
        resources = deepcopy(unresolved["resources"])
        probe = {"resources": resources}
        validate_manifest(probe)
        with tempfile.TemporaryDirectory(
            prefix=f".{workload_id}-controlled-prepare-", dir=root
        ) as temporary:
            evidence, runs, udp_receipt = _probe_response_stability(
                probe,
                Path(temporary),
                max_response_bytes=1_048_576,
                timeout_seconds=120,
                stability_runs=3,
                stability_interval_seconds=0,
            )
        required = {resource["id"] for resource in resources}
        if set(evidence["stable_resource_ids"]) != required:
            missing = ", ".join(
                str(identifier)
                for identifier in sorted(required - set(evidence["stable_resource_ids"]))
            )
            raise PreparationError(
                f"controlled local workload {workload_id} is not stable for resource IDs: "
                f"{missing or 'unexpected extra resource'}"
            )
        resources = project_stable_response_lengths(resources, evidence["expected_responses"])
        _freeze_request_headers(resources, runs)
        if require_csbuflo_rate_driver:
            _validate_controlled_csbuflo_rate_driver(
                workload_id,
                resources,
                runs=runs,
            )
        provenance = _neqo_provenance(runs)
        first = resources[0]
        origins = sorted(
            {
                origin
                for resource in resources
                if (origin := https_origin(resource["url"])) is not None
            }
        )
        source = source_metadata()
        image = os.environ.get("QCSD_LAB_IMAGE_DIGEST")
        if not isinstance(image, str) or not image.startswith("sha256:"):
            raise ValueError("controlled local preparation requires a concrete image digest")
        manifest = {
            "preparation": {
                "source_url": first["url"],
                "final_url": first["url"],
                "chromium_version": "not-applicable-deterministic-local-server",
                "settle_ms": 0,
                "observed_request_count": len(resources),
                "observed_origins": origins,
                "approved_origins": origins,
                "exclusions": [],
                "max_response_bytes": 1_048_576,
                "timeout_seconds": 120,
                "stability_runs": 3,
                "stability_profile": "live",
                "stability_defense": "none",
                "stability_seed": 0,
                "lab_source": source,
                "prepare_image_digest": image,
                "udp_payload_qualification": udp_receipt,
                "expected_responses": evidence["expected_responses"],
                **provenance,
            },
            "resources": resources,
        }
        validate_manifest(manifest)
        _create_or_verify_bytes(
            destination,
            canonical_bytes(manifest),
            f"{label} {workload_id}",
        )


def _local_prepared_manifest(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the unresolved local graph; preparation evidence is added after probes."""

    return {"resources": resources}


def _csbuflo_rate_driver_value(workload_id: str) -> str:
    """Return a stable per-workload high-entropy ASCII header value."""

    chunks: list[str] = []
    counter = 0
    while len(chunks) * hashlib.sha256().digest_size * 2 < CSBUFLO_RATE_DRIVER_VALUE_BYTES:
        chunks.append(
            hashlib.sha256(
                f"qcsd-controlled-csbuflo-rate-driver-v1:{workload_id}:{counter}".encode()
            ).hexdigest()
        )
        counter += 1
    return "".join(chunks)[:CSBUFLO_RATE_DRIVER_VALUE_BYTES]


def _controlled_csbuflo_rate_driver(identifier: int, workload_id: str) -> dict[str, Any]:
    """Build the application-only request-rate driver for controlled workloads."""

    resource = _local_resource(
        identifier,
        "https://qcsd-buflo-server-one:4433/1",
        "Fetch",
        1,
        depends_on=[0],
    )
    resource["headers"].append(
        [CSBUFLO_RATE_DRIVER_HEADER_NAME, _csbuflo_rate_driver_value(workload_id)]
    )
    return resource


def _validate_controlled_csbuflo_rate_driver(
    workload_id: str,
    resources: Sequence[Mapping[str, Any]],
    *,
    runs: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Fail closed unless the controlled-only driver has live encoded margin."""

    matches: list[Mapping[str, Any]] = []
    expected_value = _csbuflo_rate_driver_value(workload_id)
    for resource in resources:
        headers = resource.get("headers")
        if not isinstance(headers, list):
            continue
        fields = [
            header
            for header in headers
            if isinstance(header, list)
            and len(header) == 2
            and header[0] == CSBUFLO_RATE_DRIVER_HEADER_NAME
        ]
        if fields:
            if len(fields) != 1 or fields[0][1] != expected_value:
                raise ValueError(
                    f"controlled workload {workload_id} has a mutated CS-BuFLO rate driver"
                )
            matches.append(resource)
    if len(matches) != 1:
        raise ValueError(
            f"controlled workload {workload_id} must have exactly one CS-BuFLO rate driver"
        )
    driver = matches[0]
    if (
        driver.get("id") == 0
        or driver.get("id") != max(resource.get("id", -1) for resource in resources)
        or driver.get("url") != "https://qcsd-buflo-server-one:4433/1"
        or driver.get("content_length") != 1
        or driver.get("data_length") != 1
        or driver.get("chaff_priority") is not False
        or driver.get("depends_on") != [0]
    ):
        raise ValueError(
            f"controlled workload {workload_id} CS-BuFLO rate driver is not the "
            "final application-only one-byte resource"
        )
    encoded_sizes: list[int] = []
    if runs is not None:
        for run in runs:
            responses = run.get("responses")
            response = (
                next(
                    (
                        item
                        for item in responses
                        if isinstance(item, Mapping) and item.get("resource_id") == driver["id"]
                    ),
                    None,
                )
                if isinstance(responses, list)
                else None
            )
            size = response.get("request_stream_bytes") if isinstance(response, Mapping) else None
            if (
                not isinstance(response, Mapping)
                or response.get("complete") is not True
                or response.get("outcome") != "succeeded"
                or type(size) is not int
                or size < CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
            ):
                raise ValueError(
                    f"controlled workload {workload_id} CS-BuFLO rate driver did not "
                    "encode beyond the first adaptation boundary with post-boundary cells"
                )
            encoded_sizes.append(size)
    return {
        "resource_id": driver["id"],
        "header_value_bytes": len(expected_value.encode("ascii")),
        "minimum_request_stream_bytes": CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES,
        "encoded_request_stream_bytes": encoded_sizes,
    }


def _controlled_csbuflo_rate_driver_observation(
    workload_id: str, run: Mapping[str, Any]
) -> dict[str, int]:
    """Bind a controlled capture to the actual encoded application stream size."""

    expected_id = {"local-small": 1, "local-large": 4}.get(workload_id)
    if expected_id is None:
        raise ValueError(f"unexpected controlled workload for CS-BuFLO driver: {workload_id}")
    expected_value = _csbuflo_rate_driver_value(workload_id)
    responses = run.get("responses")
    matches = []
    if isinstance(responses, list):
        for response in responses:
            if not isinstance(response, Mapping):
                continue
            headers = response.get("request_headers")
            if (
                isinstance(headers, list)
                and [
                    CSBUFLO_RATE_DRIVER_HEADER_NAME,
                    expected_value,
                ]
                in headers
            ):
                matches.append(response)
    if len(matches) != 1:
        raise ValueError(
            f"controlled {workload_id} run does not contain exactly one application-only "
            "CS-BuFLO rate driver"
        )
    response = matches[0]
    size = response.get("request_stream_bytes")
    if (
        response.get("resource_id") != expected_id
        or response.get("complete") is not True
        or response.get("outcome") != "succeeded"
        or type(size) is not int
        or size < CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
    ):
        raise ValueError(
            f"controlled {workload_id} run did not transmit enough fresh application "
            "request STREAM bytes for CS-BuFLO adaptation"
        )
    return {
        "resource_id": expected_id,
        "request_stream_bytes": size,
        "boundary_bytes": CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES,
        "post_boundary_cells": (size - CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES)
        // CSBUFLO_RATE_DRIVER_CELL_BYTES,
    }


def _local_resource(
    identifier: int,
    url: str,
    resource_type: str,
    size: int,
    *,
    depends_on: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "url": url,
        "type": resource_type,
        "content_length": size,
        "data_length": size,
        "chaff_priority": identifier == 0,
        "known_valid": True,
        "depends_on": depends_on or [],
        "headers": [
            ["accept", "text/html,application/xhtml+xml"],
            ["accept-encoding", "identity"],
            ["accept-language", "en-US,en;q=0.9"],
            ["user-agent", "qcsd-controlled-local-application"],
        ],
    }


def _qualify_local_workloads(workload_root: Path, qualification_root: Path) -> None:
    _qualify_local_workloads_named(workloads_ids(), workload_root, qualification_root)


def _qualify_local_workloads_named(
    workload_ids: Sequence[str], workload_root: Path, qualification_root: Path
) -> None:
    from .chaff_qualification import qualify_response_chaff_v2

    for workload_id in workload_ids:
        destination = qualification_root / f"{workload_id}.json"
        if destination.is_file() and not destination.is_symlink():
            continue
        qualify_response_chaff_v2(
            workload_id,
            qualification_root=qualification_root,
            workload_root=workload_root,
            timeout_seconds=120,
        )


def _qualify_local_full_chaff(
    workload_root: Path,
    qualification_root: Path,
    prefix_root: Path,
) -> None:
    from .chaff_qualification import qualify_chaff

    historical = load_json(LAB_ROOT / "config/defense-params/walkie-talkie-live.json")
    profiles = {profile["real"]: profile for profile in historical["profiles"]}
    for workload_id in ("simple", "complex"):
        profile = _current_regression_walkie_talkie_profile(
            profiles[workload_id], historical["packet_size"]
        )
        _write_regression_prefix_spec(
            prefix_root / f"{workload_id}.json",
            workload_id,
            profile["bursts"],
            application_manifest=load_json(workload_root / f"{workload_id}.json"),
        )
        destination = qualification_root / f"{workload_id}.json"
        if destination.is_file() and not destination.is_symlink():
            continue
        qualify_chaff(
            workload_id,
            workload_root=workload_root,
            qualification_root=qualification_root,
            prefix_spec_root=prefix_root,
            timeout_seconds=120,
        )


def _write_regression_prefix_spec(
    path: Path,
    workload_id: str,
    bursts: list[dict[str, int]],
    *,
    application_manifest: Mapping[str, Any],
) -> None:
    from .chaff_qualification import prefix_pack_spec

    historical = LAB_ROOT / "config/defense-params/walkie-talkie-live.json"
    value = prefix_pack_spec(
        workload_id,
        load_json(historical),
        source_walkie_talkie_artifact_sha256=sha256_file(historical),
        application_manifest=application_manifest,
    )
    if value["numeric_profile"] != {"packet_size": 1_200, "bursts": bursts}:
        raise ValueError(
            f"local regression prefix specification differs from runtime mould: {workload_id}"
        )
    _create_or_verify_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(),
        f"local regression prefix specification {workload_id}",
    )


def _current_regression_walkie_talkie_profile(
    historical: Mapping[str, Any], packet_size: int
) -> dict[str, Any]:
    from .fitting_walkie_talkie import BurstPair, mold, mold_padding_cost

    profile = deepcopy(dict(historical))

    def envelope(side: str) -> tuple[Any, ...]:
        batch_ends = set(profile["batch_ends"][side])
        return tuple(
            BurstPair(
                outgoing=burst["outgoing"],
                incoming=burst["incoming"],
                batch_end=index in batch_ends,
            )
            for index, burst in enumerate(profile["source_envelopes"][side])
        )

    real = envelope("real")
    decoy = envelope("decoy")
    molded = tuple(mold(real, decoy))
    profile["bursts"] = [
        {"outgoing": burst.outgoing, "incoming": burst.incoming} for burst in molded
    ]
    profile["molded_batch_ends"] = [index for index, burst in enumerate(molded) if burst.batch_end]
    profile["matching_cost_packets"] = mold_padding_cost(real, decoy)
    profile["total_scheduled_bytes"] = (
        sum(burst.outgoing + burst.incoming for burst in molded) * packet_size
    )
    return profile


def _write_regression_walkie_talkie(
    workload_root: Path,
    qualification_root: Path,
    prefix_root: Path,
    parameter_root: Path,
) -> Path:
    from .chaff_qualification import load_qualified_chaff
    from .fitting_walkie_talkie import receiver_continuation_contract
    from .manifest import canonical_bytes

    historical_path = LAB_ROOT / "config/defense-params/walkie-talkie-live.json"
    historical = load_json(historical_path)
    source_profiles = {profile["real"]: profile for profile in historical["profiles"]}
    profiles: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    for workload_id in ("simple", "complex"):
        sidecar = qualification_root / f"{workload_id}.json"
        spec = prefix_root / f"{workload_id}.json"
        source = workload_root / f"{workload_id}.json"
        qualified = load_qualified_chaff(
            sidecar,
            workload_id=workload_id,
            base_manifest_path=source,
            prefix_spec_path=spec,
            require_current_implementation=True,
        )
        profile = _current_regression_walkie_talkie_profile(
            source_profiles[workload_id], historical["packet_size"]
        )
        decoy = f"controlled-decoy-{workload_id}"
        profile["real"] = workload_id
        profile["decoy"] = decoy
        profiles.append(profile)
        binding = {
            "workload_id": workload_id,
            "chaff_qualification_sidecar_sha256": qualified.sidecar_sha256,
            "prefix_pack_spec_sha256": sha256_file(spec),
            "qualified_chaff_manifest_sha256": qualified.manifest_sha256,
            "application_resource_id": qualified.manifest["application_resource_id"],
            "selected_chaff_resource_id": qualified.manifest["selected_chaff_resource_id"],
            "qualified_parallel_chaff_streams": qualified.manifest[
                "qualified_parallel_chaff_streams"
            ],
            "walkie_talkie_required_chaff_streams": qualified.manifest[
                "walkie_talkie_required_chaff_streams"
            ],
        }
        bindings.append(binding)
        bindings.append(
            {
                **binding,
                "workload_id": decoy,
                "chaff_qualification_sidecar_sha256": _canonical_digest([decoy, "sidecar"]),
                "prefix_pack_spec_sha256": _canonical_digest([decoy, "prefix"]),
                "qualified_chaff_manifest_sha256": _canonical_digest([decoy, "manifest"]),
            }
        )
    parameter = deepcopy(historical)
    parameter.update(
        {
            "schema_version": 6,
            "generated_by": "qcsd-buflo-study-controlled-regression-v1",
            "receiver_continuation": receiver_continuation_contract(),
            "profiles": profiles,
            "qualification_bindings": bindings,
        }
    )
    path = parameter_root / "walkie-talkie-controlled-v6.json"
    encoded = canonical_bytes(parameter)
    _create_or_verify_bytes(path, encoded, "controlled regression Walkie-Talkie parameters")
    provenance = {
        "schema_version": 1,
        "artifact_type": "qcsd-controlled-regression-parameters",
        "status": "controlled-test-only",
        "production_ready": False,
        "defense_kind": "walkie_talkie",
        "qcsd_profile": "live",
        "udp_payload_ceiling": 1_200,
        "parameter_file": {"path": path.name, "sha256": sha256_file(path)},
        "evidence_class": "nonformal-regression",
        "workload_sha256": {
            workload_id: sha256_file(workload_root / f"{workload_id}.json")
            for workload_id in ("simple", "complex")
        },
    }
    _create_or_verify_bytes(
        path.with_suffix(path.suffix + ".provenance.json"),
        (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode(),
        "controlled regression Walkie-Talkie provenance",
    )
    return path


def _regression_multi_origin_projection(
    surrogate: Mapping[str, Any],
    application: Mapping[str, Any],
) -> dict[str, Any]:
    """Prove that only the declared secondary origins differ from the WT surrogate."""

    from urllib.parse import urlsplit

    from .manifest import canonical_bytes, https_origin, validate_research_preparation

    surrogate_value = deepcopy(dict(surrogate))
    application_value = deepcopy(dict(application))
    validate_research_preparation(surrogate_value, workload_id="complex")
    validate_research_preparation(application_value, workload_id="complex")
    surrogate_resources = surrogate_value["resources"]
    application_resources = application_value["resources"]
    if len(surrogate_resources) != 4 or len(application_resources) != 4:
        raise ValueError("multi-origin compatibility requires the exact four-resource graph")
    surrogate_by_id = {resource["id"]: resource for resource in surrogate_resources}
    application_by_id = {resource["id"]: resource for resource in application_resources}
    if set(surrogate_by_id) != {0, 1, 2, 3} or set(application_by_id) != {0, 1, 2, 3}:
        raise ValueError("multi-origin compatibility resource identities drifted")
    expected_application_origins = {
        0: MULTI_ORIGIN_COMPATIBILITY_ORIGINS[0],
        1: MULTI_ORIGIN_COMPATIBILITY_ORIGINS[0],
        2: MULTI_ORIGIN_COMPATIBILITY_ORIGINS[1],
        3: MULTI_ORIGIN_COMPATIBILITY_ORIGINS[1],
    }
    projected_resources: list[dict[str, Any]] = []
    for resource_id in range(4):
        source = surrogate_by_id[resource_id]
        target = application_by_id[resource_id]
        source_url = urlsplit(str(source["url"]))
        target_url = urlsplit(str(target["url"]))
        source_without_url = {key: value for key, value in source.items() if key != "url"}
        target_without_url = {key: value for key, value in target.items() if key != "url"}
        if (
            source_without_url != target_without_url
            or source_url.scheme != "https"
            or target_url.scheme != "https"
            or (source_url.path, source_url.query, source_url.fragment)
            != (target_url.path, target_url.query, target_url.fragment)
            or https_origin(source["url"]) != MULTI_ORIGIN_COMPATIBILITY_ORIGINS[0]
            or https_origin(target["url"]) != expected_application_origins[resource_id]
        ):
            raise ValueError(
                f"multi-origin compatibility resource {resource_id} differs beyond origin"
            )
        projected_resources.append(
            {
                "resource_id": resource_id,
                "surrogate_origin": https_origin(source["url"]),
                "application_origin": https_origin(target["url"]),
                "path": target_url.path,
                "resource_metadata_sha256": hashlib.sha256(
                    canonical_bytes(target_without_url)
                ).hexdigest(),
            }
        )
    surrogate_preparation = surrogate_value["preparation"]
    application_preparation = application_value["preparation"]
    if (
        surrogate_preparation["source_url"] != application_preparation["source_url"]
        or surrogate_preparation["final_url"] != application_preparation["final_url"]
        or surrogate_preparation["expected_responses"]
        != application_preparation["expected_responses"]
        or surrogate_preparation["approved_origins"] != [MULTI_ORIGIN_COMPATIBILITY_ORIGINS[0]]
        or application_preparation["approved_origins"] != list(MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
        or application_preparation["observed_origins"] != list(MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
    ):
        raise ValueError("multi-origin compatibility prepared response/origin binding drifted")
    return {
        "schema_version": 1,
        "policy": (
            "strict-single-origin-prefix-surrogate-with-identical-resource-graph-and-"
            "prepared-response-identities;secondary-origin-difference-proved-live"
        ),
        "surrogate_origins": [MULTI_ORIGIN_COMPATIBILITY_ORIGINS[0]],
        "application_origins": list(MULTI_ORIGIN_COMPATIBILITY_ORIGINS),
        "resource_ids": [0, 1, 2, 3],
        "resources": projected_resources,
        "expected_responses_sha256": hashlib.sha256(
            canonical_bytes(application_preparation["expected_responses"])
        ).hexdigest(),
        "only_declared_origins_differ": True,
    }


def _regression_multi_origin_run_identity(
    run: Mapping[str, Any],
    application: Mapping[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    """Validate exact endpoints and application responses for one compatibility mode."""

    from .manifest import https_origin

    if mode not in MULTI_ORIGIN_COMPATIBILITY_MODES:
        raise ValueError("multi-origin compatibility mode is not one of the exact nine")
    endpoints = run.get("endpoints")
    if not isinstance(endpoints, list):
        raise ValueError(  # noqa: TRY004 - malformed evidence is one validation failure class.
            "multi-origin compatibility run has no endpoint array"
        )
    endpoint_coverage = _controlled_endpoint_coverage(endpoints, workload="local-large")
    resources = application.get("resources")
    preparation = application.get("preparation")
    expected_responses = (
        preparation.get("expected_responses") if isinstance(preparation, Mapping) else None
    )
    responses = run.get("responses")
    if (
        not isinstance(resources, list)
        or not isinstance(expected_responses, list)
        or not isinstance(responses, list)
    ):
        raise ValueError(  # noqa: TRY004 - malformed evidence is one validation failure class.
            "multi-origin compatibility response evidence is absent"
        )
    resources_by_id = {
        resource.get("id"): resource
        for resource in resources
        if isinstance(resource, Mapping) and type(resource.get("id")) is int
    }
    expected_by_id = {
        response.get("resource_id"): response
        for response in expected_responses
        if isinstance(response, Mapping) and type(response.get("resource_id")) is int
    }
    observed_by_id = {
        response.get("resource_id"): response
        for response in responses
        if isinstance(response, Mapping) and type(response.get("resource_id")) is int
    }
    if (
        set(resources_by_id) != {0, 1, 2, 3}
        or set(expected_by_id) != set(resources_by_id)
        or set(observed_by_id) != set(resources_by_id)
        or len(responses) != len(observed_by_id)
    ):
        raise ValueError("multi-origin compatibility run lost or duplicated a resource")
    identities: list[dict[str, Any]] = []
    observed_origins: set[str] = set()
    for resource_id in range(4):
        resource = resources_by_id[resource_id]
        expected = expected_by_id[resource_id]
        observed = observed_by_id[resource_id]
        origin = https_origin(resource.get("url"))
        if (
            origin not in MULTI_ORIGIN_COMPATIBILITY_ORIGINS
            or observed.get("url") != resource.get("url")
            or observed.get("status") != expected.get("status")
            or observed.get("bytes") != expected.get("bytes")
            or observed.get("body_sha256") != expected.get("body_sha256")
            or observed.get("complete") is not True
            or observed.get("outcome") != "succeeded"
        ):
            raise ValueError(
                f"multi-origin compatibility resource {resource_id} response identity failed"
            )
        observed_origins.add(str(origin))
        identities.append(
            {
                "resource_id": resource_id,
                "origin": origin,
                "url": resource["url"],
                "status": expected["status"],
                "bytes": expected["bytes"],
                "body_sha256": expected["body_sha256"],
            }
        )
    if observed_origins != set(MULTI_ORIGIN_COMPATIBILITY_ORIGINS):
        raise ValueError("multi-origin compatibility run did not retain both resource origins")
    return {
        "mode": mode,
        "endpoint_coverage": endpoint_coverage,
        "resource_count": len(identities),
        "resource_ids": [identity["resource_id"] for identity in identities],
        "resources": identities,
        "exact_prepared_response_identity": True,
        "passed": True,
    }


def _project_regression_chaff_manifest(
    qualified_manifest: Mapping[str, Any],
    *,
    surrogate_sha256: str,
    application_sha256: str,
) -> dict[str, Any]:
    """Retarget only the application-source hash of a strict root-prefix proof."""

    projected = deepcopy(dict(qualified_manifest))
    if (
        projected.get("schema_version") != 2
        or projected.get("application_workload_sha256") != surrogate_sha256
        or projected.get("application_resource_id") != 0
        or projected.get("selected_chaff_resource_id") != 0
        or not isinstance(projected.get("resources"), list)
        or len(projected["resources"]) != 1
    ):
        raise ValueError("multi-origin compatibility prefix-qualified manifest is invalid")
    projected["application_workload_sha256"] = application_sha256
    return projected


def _regression_multi_origin_walkie_talkie_value(
    source: Mapping[str, Any], *, projected_manifest_sha256: str
) -> dict[str, Any]:
    parameter = deepcopy(dict(source))
    if (
        not isinstance(parameter, dict)
        or parameter.get("schema_version") != 6
        or parameter.get("generated_by") != "qcsd-buflo-study-controlled-regression-v1"
        or not isinstance(parameter.get("qualification_bindings"), list)
    ):
        raise ValueError("controlled Walkie-Talkie source parameter is invalid")
    matches = [
        binding
        for binding in parameter["qualification_bindings"]
        if isinstance(binding, dict) and binding.get("workload_id") == "complex"
    ]
    if len(matches) != 1:
        raise ValueError("controlled Walkie-Talkie source lacks one complex binding")
    matches[0]["qualified_chaff_manifest_sha256"] = projected_manifest_sha256
    parameter["generated_by"] = "qcsd-buflo-study-multi-origin-compatibility-v1"
    return parameter


def _write_regression_multi_origin_walkie_talkie(
    source_path: Path,
    destination: Path,
    provenance_path: Path,
    *,
    application_sha256: str,
    projected_manifest_sha256: str,
) -> None:
    """Bind the strict prefix proof to the separately qualified live workload."""

    from .manifest import canonical_bytes

    parameter = _regression_multi_origin_walkie_talkie_value(
        load_json(source_path),
        projected_manifest_sha256=projected_manifest_sha256,
    )
    encoded = canonical_bytes(parameter)
    _create_or_verify_bytes(
        destination,
        encoded,
        "multi-origin compatibility Walkie-Talkie parameters",
    )
    provenance = {
        "schema_version": 1,
        "artifact_type": "qcsd-controlled-regression-parameters",
        "status": "controlled-test-only",
        "production_ready": False,
        "defense_kind": "walkie_talkie",
        "qcsd_profile": "live",
        "udp_payload_ceiling": 1_200,
        "parameter_file": {
            "path": destination.name,
            "sha256": sha256_file(destination),
        },
        "evidence_class": "nonformal-regression",
        "workload_sha256": {"complex": application_sha256},
    }
    _create_or_verify_bytes(
        provenance_path,
        (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode(),
        "multi-origin compatibility Walkie-Talkie provenance",
    )
    validate_parameter_artifact(
        destination,
        provenance_path=provenance_path,
        expected_kind="walkie_talkie",
        allow_reviewed_fixture=True,
        expected_qcsd_profile="live",
        expected_udp_payload_ceiling=1_200,
        expected_workloads={"complex": application_sha256},
    )


def _regression_multi_origin_defenses(
    walkie_talkie: Path,
    walkie_talkie_provenance: Path,
    *,
    application_sha256: str,
) -> tuple[Any, ...]:
    """Resolve the exact nine test-only runtime identities without campaign mutation."""

    from .capture_session import Defense
    from .orchestrator import _validate_static_schedule
    from .parameters import parameter_provenance_path

    static = LAB_ROOT / "config/defense-params/static-control-1200.csv"
    _validate_static_schedule(static, udp_payload_ceiling=1_200)

    def reviewed(
        name: str,
        kind: str,
        path: Path,
        *,
        workloads: Sequence[str] | Mapping[str, str] | None = None,
        provenance: Path | None = None,
    ) -> Any:
        artifact = validate_parameter_artifact(
            path,
            provenance_path=provenance,
            expected_kind=kind,
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1_200,
            expected_workloads=workloads,
        )
        return Defense(
            name=name,
            kind=kind,
            baseline=False,
            parameters=str(path),
            parameters_path=artifact.path,
            parameters_sha256=artifact.sha256,
            parameters_provenance=str(artifact.provenance_path),
            parameters_provenance_path=artifact.provenance_path,
            parameters_provenance_sha256=artifact.provenance_sha256,
            parameters_input_policy=artifact.input_policy,
        )

    def candidate(name: str, kind: str, path: Path) -> Any:
        artifact = validate_parameter_artifact(
            path,
            expected_kind=kind,
            allow_study_candidate=True,
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
        )
        return Defense(
            name=name,
            kind=kind,
            baseline=False,
            parameters=str(path),
            parameters_path=artifact.path,
            parameters_sha256=artifact.sha256,
            parameters_provenance=str(artifact.provenance_path),
            parameters_provenance_path=artifact.provenance_path,
            parameters_provenance_sha256=artifact.provenance_sha256,
            parameters_input_policy=artifact.input_policy,
        )

    defenses = (
        Defense(name="undefended", kind="none", baseline=True),
        Defense(
            name="static",
            kind="static",
            baseline=False,
            schedule=str(static),
            schedule_path=static,
            schedule_sha256=sha256_file(static),
            mode="chaff-only",
        ),
        Defense(name="front", kind="front", baseline=False),
        Defense(name="tamaraw", kind="tamaraw", baseline=False),
        reviewed(
            "traffic-morphing",
            "traffic_morphing",
            LAB_ROOT / "config/defense-params/traffic-morphing-live.json",
            workloads=("complex",),
        ),
        reviewed(
            "wtf-pad",
            "wtf_pad",
            LAB_ROOT / "config/defense-params/wtfpad-live.json",
        ),
        reviewed(
            "walkie-talkie",
            "walkie_talkie",
            walkie_talkie,
            provenance=walkie_talkie_provenance,
            workloads={"complex": application_sha256},
        ),
        candidate("buflo", "buflo", PARAMETER_FILES["buflo"][1]),
        candidate("cs-buflo", "cs_buflo", PARAMETER_FILES["cs-buflo"][1]),
    )
    if tuple(defense.name for defense in defenses) != MULTI_ORIGIN_COMPATIBILITY_MODES:
        raise AssertionError("multi-origin compatibility defense order drifted")
    # Keep the source-adjacent provenance rule explicit for reviewed artifacts.
    if any(
        defense.parameters_path is not None
        and defense.name != "walkie-talkie"
        and defense.parameters_provenance_path != parameter_provenance_path(defense.parameters_path)
        for defense in defenses
    ):
        raise AssertionError("multi-origin compatibility parameter provenance drifted")
    return defenses


def _regression_multi_origin_raw_attempt_inventory(attempt: Path) -> dict[str, str]:
    if attempt.is_symlink() or not attempt.is_dir():
        raise ValueError("multi-origin compatibility attempt is not a regular directory")
    files: dict[str, str] = {}
    for path in sorted(attempt.rglob("*")):
        if path.is_symlink():
            raise ValueError("multi-origin compatibility attempt contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(
                "multi-origin compatibility attempt contains a special filesystem entry"
            )
        files[path.relative_to(attempt).as_posix()] = sha256_file(path)
    if not files:
        raise ValueError("multi-origin compatibility attempt has no terminal evidence")
    return files


def _regression_multi_origin_attempt_inventory(attempt: Path) -> dict[str, str]:
    files = _regression_multi_origin_raw_attempt_inventory(attempt)
    required = {
        "attempt.json",
        "captures/direct-quic.pcapng",
        "traces/direct-quic.csv",
        "neqo/run.json",
        "neqo/packets.csv",
        "neqo/events.csv",
        "neqo/schedule.csv",
    }
    if not required <= set(files):
        raise ValueError("multi-origin compatibility attempt lacks required evidence files")
    return files


def _validate_regression_multi_origin_checkpoint(
    value: object,
    *,
    require_complete: bool,
) -> dict[str, str]:
    """Validate the exact resumable accepted-attempt map without trusting paths."""

    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "artifact_type", "accepted_attempts"}
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != MULTI_ORIGIN_COMPATIBILITY_CHECKPOINT_TYPE
        or not isinstance(value.get("accepted_attempts"), Mapping)
    ):
        raise ValueError("multi-origin compatibility checkpoint is invalid")
    accepted = value["accepted_attempts"]
    if require_complete and set(accepted) != set(MULTI_ORIGIN_COMPATIBILITY_MODES):
        raise ValueError("multi-origin compatibility checkpoint is incomplete")
    if not set(accepted) <= set(MULTI_ORIGIN_COMPATIBILITY_MODES):
        raise ValueError("multi-origin compatibility checkpoint has an unknown mode")
    normalized: dict[str, str] = {}
    for mode, relative in accepted.items():
        expected_prefix = Path("attempts") / str(mode)
        if (
            not isinstance(mode, str)
            or not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or Path(relative).parent != expected_prefix
            or re.fullmatch(r"attempt-(0[1-3])", Path(relative).name) is None
        ):
            raise ValueError("multi-origin compatibility checkpoint path is invalid")
        normalized[mode] = relative
    return normalized


def _regression_multi_origin_persist_rejection(
    attempt: Path,
    error: BaseException,
    *,
    stage: str,
) -> None:
    """Persist a deterministic reason when the collector did not already do so."""

    result_path = attempt / "attempt.json"
    if result_path.is_file() and not result_path.is_symlink():
        try:
            result = load_json(result_path)
        except (OSError, TypeError, ValueError):
            result = None
        if (
            isinstance(result, Mapping)
            and result.get("success") is False
            and isinstance(result.get("failure"), Mapping)
            and bool(result["failure"])
        ):
            return
    value = {
        "schema_version": 1,
        "artifact_type": MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": stage,
            "type": type(error).__name__,
            "message": str(error) or type(error).__name__,
        },
    }
    path = attempt / "multi-origin-compatibility-error.json"
    if path.exists() or path.is_symlink():
        _regression_multi_origin_rejection_failure(attempt)
        return
    atomic_json(path, value)


def _regression_multi_origin_rejection_failure(attempt: Path) -> dict[str, Any]:
    """Return the exact persisted reason for one rejected compatibility attempt."""

    error_path = attempt / "multi-origin-compatibility-error.json"
    if error_path.exists() or error_path.is_symlink():
        if error_path.is_symlink() or not error_path.is_file():
            raise ValueError("multi-origin compatibility rejection reason is unsafe")
        value = load_json(error_path)
        if (
            not isinstance(value, Mapping)
            or set(value) != {"schema_version", "artifact_type", "failure"}
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("artifact_type") != MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE
            or not isinstance(value.get("failure"), Mapping)
            or set(value["failure"]) != {"stage", "type", "message"}
            or not all(
                isinstance(value["failure"].get(field), str) and bool(value["failure"][field])
                for field in ("stage", "type", "message")
            )
        ):
            raise ValueError("multi-origin compatibility rejection reason is malformed")
        return {
            "source": "multi-origin-compatibility-error.json",
            "details": dict(value["failure"]),
        }
    result_path = attempt / "attempt.json"
    if result_path.is_symlink() or not result_path.is_file():
        raise ValueError("multi-origin compatibility rejected attempt lacks its reason")
    result = load_json(result_path)
    failure = result.get("failure") if isinstance(result, Mapping) else None
    if (
        not isinstance(result, Mapping)
        or result.get("success") is not False
        or not isinstance(failure, Mapping)
        or not failure
    ):
        raise ValueError("multi-origin compatibility rejected attempt lacks its reason")
    return {"source": "attempt.json", "details": dict(failure)}


def _regression_multi_origin_has_rejection_marker(attempt: Path) -> bool:
    path = attempt / "multi-origin-compatibility-error.json"
    return path.exists() or path.is_symlink()


def _regression_multi_origin_attempt_record(
    root: Path,
    attempt: Path,
    application_path: Path,
    projected_chaff_path: Path,
    defense: Any,
    *,
    seed: int,
    historical_candidate_source: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Classify and hash one attempt; accepted evidence is returned separately."""

    match = re.fullmatch(r"attempt-(0[1-3])", attempt.name)
    if match is None:
        raise ValueError("multi-origin compatibility attempt name is invalid")
    files = _regression_multi_origin_raw_attempt_inventory(attempt)
    evidence: dict[str, Any] | None = None
    if _regression_multi_origin_has_rejection_marker(attempt):
        failure: dict[str, Any] | None = _regression_multi_origin_rejection_failure(attempt)
        outcome = "rejected"
    else:
        try:
            evidence = _regression_multi_origin_attempt_evidence(
                attempt,
                application_path,
                projected_chaff_path,
                defense,
                seed=seed,
                historical_candidate_source=historical_candidate_source,
            )
        except (OSError, TypeError, ValueError):
            failure = _regression_multi_origin_rejection_failure(attempt)
            outcome = "rejected"
        else:
            failure = None
            outcome = "accepted"
    return (
        {
            "attempt": attempt.relative_to(root).as_posix(),
            "attempt_index": int(match.group(1)),
            "outcome": outcome,
            "failure": failure,
            "file_count": len(files),
            "files": files,
            "files_sha256": _canonical_digest(files),
        },
        evidence,
    )


def _regression_multi_origin_attempt_ledgers(
    root: Path,
    application_path: Path,
    projected_chaff_path: Path,
    defenses: Sequence[Any],
    accepted_attempts: Mapping[str, str],
    samples: Sequence[Mapping[str, Any]],
    *,
    historical_candidate_source: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Close the exact on-disk attempt tree through each mode's acceptance."""

    attempts_root = root / "attempts"
    if attempts_root.is_symlink() or not attempts_root.is_dir():
        raise ValueError("multi-origin compatibility attempts root is invalid")
    expected_modes = {str(defense.name) for defense in defenses}
    actual_modes: set[str] = set()
    for path in attempts_root.iterdir():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("multi-origin compatibility attempts root contains an unsafe entry")
        actual_modes.add(path.name)
    if actual_modes != expected_modes:
        raise ValueError("multi-origin compatibility attempt modes are not exact")
    sample_by_mode = {
        str(sample.get("mode")): sample for sample in samples if isinstance(sample, Mapping)
    }
    if set(sample_by_mode) != expected_modes or set(accepted_attempts) != expected_modes:
        raise ValueError("multi-origin compatibility accepted mode binding is incomplete")

    ledgers: list[dict[str, Any]] = []
    for defense in defenses:
        mode = str(defense.name)
        mode_root = attempts_root / mode
        attempts: dict[int, Path] = {}
        for path in mode_root.iterdir():
            match = re.fullmatch(r"attempt-(0[1-3])", path.name)
            if path.is_symlink() or not path.is_dir() or match is None:
                raise ValueError(f"multi-origin compatibility {mode} attempt inventory is unsafe")
            attempts[int(match.group(1))] = path
        if not attempts or sorted(attempts) != list(range(1, len(attempts) + 1)):
            raise ValueError(
                f"multi-origin compatibility {mode} attempts are not exact and contiguous"
            )
        seed = _stable_seed("buflo-regression-multi-origin-v1", mode)
        records: list[dict[str, Any]] = []
        accepted_evidence: list[dict[str, Any]] = []
        for attempt_index in sorted(attempts):
            record, evidence = _regression_multi_origin_attempt_record(
                root,
                attempts[attempt_index],
                application_path,
                projected_chaff_path,
                defense,
                seed=seed,
                historical_candidate_source=historical_candidate_source,
            )
            records.append(record)
            if evidence is not None:
                accepted_evidence.append(evidence)
        if (
            len(accepted_evidence) != 1
            or records[-1]["outcome"] != "accepted"
            or any(record["outcome"] != "rejected" for record in records[:-1])
        ):
            raise ValueError(f"multi-origin compatibility {mode} attempt outcomes are not terminal")
        accepted = records[-1]["attempt"]
        sample = sample_by_mode[mode]
        if (
            accepted_attempts[mode] != accepted
            or sample.get("attempt") != accepted
            or sample.get("files") != records[-1]["files"]
            or sample.get("files_sha256") != records[-1]["files_sha256"]
        ):
            raise ValueError(f"multi-origin compatibility {mode} accepted attempt binding changed")
        ledgers.append(
            {
                "mode": mode,
                "accepted_attempt": accepted,
                "attempt_count": len(records),
                "rejected_attempts": len(records) - 1,
                "attempts": records,
            }
        )
    return ledgers


def _validate_regression_multi_origin_attempt_ledger_receipt(
    value: object,
    expected: Sequence[Mapping[str, Any]],
) -> None:
    if not isinstance(value, list) or value != list(expected):
        raise ValueError("multi-origin compatibility attempt ledger changed")


def _regression_multi_origin_attempt_evidence(
    attempt: Path,
    application_path: Path,
    projected_chaff_path: Path,
    defense: Any,
    *,
    seed: int,
    historical_candidate_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    from types import SimpleNamespace

    from .capture_session import _runner_result_complete, _validate_run_binding
    from .manifest import runtime_manifest
    from .orchestrator import _intrinsic_fidelity_failure

    if _regression_multi_origin_has_rejection_marker(attempt):
        _regression_multi_origin_rejection_failure(attempt)
        raise ValueError("multi-origin compatibility attempt is durably rejected")

    application = load_json(application_path)
    runtime_path = attempt.parent.parent.parent / "inputs/application/runtime-complex.json"
    expected_runtime = runtime_manifest(application)
    if (
        runtime_path.is_symlink()
        or not runtime_path.is_file()
        or load_json(runtime_path) != expected_runtime
    ):
        raise ValueError("multi-origin compatibility runtime workload binding is invalid")
    result_path = attempt / "attempt.json"
    run_path = attempt / "neqo/run.json"
    if result_path.is_symlink() or run_path.is_symlink():
        raise ValueError("multi-origin compatibility attempt evidence cannot be a symlink")
    result = load_json(result_path)
    run = load_json(run_path)
    expected_ids = {resource["id"] for resource in application["resources"]}
    if (
        not isinstance(result, dict)
        or result.get("success") is not True
        or result.get("runner_complete") is not True
        or result.get("runner_binding_valid") is not True
        or result.get("endpoint_count") != 2
        or result.get("expected_endpoint_count") != 2
        or result.get("endpoint_count_valid") is not True
        or not _runner_result_complete(run, expected_ids)
    ):
        raise ValueError("multi-origin compatibility attempt is not runner/capture eligible")
    qcsd_profile = "research-1200" if defense.name in {"buflo", "cs-buflo"} else "live"
    limits = SimpleNamespace(
        timeout_seconds=120,
        max_response_bytes=1_048_576,
        capture_seconds=180,
        capture_megabytes=64,
        max_attempts=3,
        per_origin_cooldown_seconds=0,
        settle_seconds=1,
    )
    context = SimpleNamespace(
        qcsd_profile=qcsd_profile,
        request_policy="as-defined",
        limits=limits,
        udp_payload_ceiling=1_200,
    )
    _validate_run_binding(
        run,
        manifest=runtime_path,
        chaff_manifest=None if defense.baseline else projected_chaff_path,
        application_workload_source=None if defense.baseline else application_path,
        workload_id="complex",
        defense=defense,
        seed=seed,
        context=context,
        historical_candidate_source=historical_candidate_source,
    )
    sample = {
        "sample_id": f"multi-origin-{defense.name}",
        "defense": defense.name,
        "runtime_kind": defense.kind,
    }
    fidelity_failure = _intrinsic_fidelity_failure(sample, result, attempt)
    if fidelity_failure is not None:
        raise ValueError(
            "multi-origin compatibility attempt failed normal fidelity eligibility: "
            f"{fidelity_failure}"
        )
    identity = _regression_multi_origin_run_identity(
        run,
        application,
        mode=defense.name,
    )
    files = _regression_multi_origin_attempt_inventory(attempt)
    return {
        "mode": defense.name,
        "runtime_kind": defense.kind,
        "seed": seed,
        "attempt": attempt.as_posix(),
        "attempt_json_sha256": files["attempt.json"],
        "file_count": len(files),
        "files": files,
        "files_sha256": _canonical_digest(files),
        "identity": identity,
        "fidelity_eligible": True,
        "passed": True,
    }


def _regression_multi_origin_existing_attempt_evidence(
    attempt: Path,
    application_path: Path,
    projected_chaff_path: Path,
    defense: Any,
    *,
    seed: int,
) -> dict[str, Any] | None:
    """Resume only a terminal accepted or durably rejected existing attempt."""

    if _regression_multi_origin_has_rejection_marker(attempt):
        _regression_multi_origin_rejection_failure(attempt)
        return None
    try:
        return _regression_multi_origin_attempt_evidence(
            attempt,
            application_path,
            projected_chaff_path,
            defense,
            seed=seed,
        )
    except (OSError, TypeError, ValueError):
        _regression_multi_origin_rejection_failure(attempt)
        return None


def _regression_multi_origin_runtime_inputs(defenses: Sequence[Any]) -> dict[str, Any]:
    inputs: dict[str, Any] = {}
    for defense in defenses:
        value: dict[str, Any] = {
            "runtime_kind": defense.kind,
            "baseline": defense.baseline,
        }
        if defense.schedule_path is not None:
            value.update(
                {
                    "input_type": "static-schedule",
                    "sha256": sha256_file(defense.schedule_path),
                    "mode": defense.mode,
                }
            )
        elif defense.parameters_path is not None:
            if defense.parameters_provenance_path is None:
                raise ValueError("multi-origin parameter provenance is absent")
            value.update(
                {
                    "input_type": "parameter-artifact",
                    "sha256": sha256_file(defense.parameters_path),
                    "provenance_sha256": sha256_file(defense.parameters_provenance_path),
                    "input_policy": defense.parameters_input_policy,
                }
            )
        else:
            value["input_type"] = "source-bound"
        inputs[defense.name] = value
    if tuple(inputs) != MULTI_ORIGIN_COMPATIBILITY_MODES:
        raise ValueError("multi-origin runtime input inventory is not the exact nine modes")
    return inputs


def _regression_result_bindings(result_roots: Sequence[Path]) -> list[dict[str, Any]]:
    from .verification import verify_result

    records: list[dict[str, Any]] = []
    by_name: dict[str, Any] = {}
    for value in result_roots:
        verified = verify_result(Path(value))
        if verified.experiment["name"] in by_name:
            raise ValueError("regression compatibility binding contains a duplicate result")
        by_name[verified.experiment["name"]] = verified
    if set(by_name) != set(LOCAL_STAGE_RESULT_NAMES["regression"]):
        raise ValueError("regression compatibility binding lacks the exact 18-sample shards")
    for name in LOCAL_STAGE_RESULT_NAMES["regression"]:
        verified = by_name[name]
        campaign_path = verified.root / "inputs/campaign.yml"
        if campaign_path.is_symlink() or not campaign_path.is_file():
            raise ValueError("regression compatibility binding lacks its frozen campaign")
        campaign = yaml.safe_load(campaign_path.read_text(encoding="utf-8"))
        controlled = campaign.get("study_controlled") if isinstance(campaign, Mapping) else None
        validate_controlled_campaign_receipt(controlled)
        records.append(
            {
                "name": name,
                "root": str(verified.root.resolve()),
                "evidence_sha256": sha256_file(verified.root / "evidence.sha256"),
                "controlled_receipt_sha256": _canonical_digest(controlled),
            }
        )
    return records


def _execute_regression_multi_origin_compatibility(
    destination: Path,
    result_roots: Sequence[Path],
    *,
    regression_receipt: Mapping[str, Any],
    walkie_talkie: Path,
    workload_root: Path,
    qualification_root: Path,
    prefix_root: Path,
) -> Path:
    """Run/resume the excluded nine-cell two-origin compatibility proof."""

    from types import SimpleNamespace

    from . import capture_session
    from .chaff_qualification import (
        load_qualified_chaff,
        load_response_qualified_chaff,
    )
    from .manifest import canonical_bytes, runtime_manifest

    root = destination / "multi-origin-nine-mode-compatibility"
    receipt_path = root / "receipt.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        validate_regression_multi_origin_compatibility(receipt_path, result_roots)
        return receipt_path
    for directory in (
        root,
        root / "inputs/application",
        root / "inputs/application-response-qualification",
        root / "inputs/surrogate/workloads",
        root / "inputs/surrogate/chaff-qualifications",
        root / "inputs/surrogate/chaff-prefix-specs",
        root / "inputs/surrogate/chaff-manifests",
        root / "inputs/defense-parameters",
        root / "attempts",
    ):
        if directory.is_symlink():
            raise ValueError(f"multi-origin compatibility path cannot be a symlink: {directory}")
        directory.mkdir(parents=True, exist_ok=True)

    application_root = root / "inputs/application"
    _create_regression_multi_origin_workload(application_root)
    application_path = application_root / "complex.json"
    application = load_json(application_path)
    runtime_path = application_root / "runtime-complex.json"
    _create_or_verify_bytes(
        runtime_path,
        canonical_bytes(runtime_manifest(application)),
        "multi-origin compatibility runtime workload",
    )

    response_root = root / "inputs/application-response-qualification"
    response_sidecar = response_root / "complex.json"
    if not response_sidecar.exists() and not response_sidecar.is_symlink():
        _qualify_local_workloads_named(("complex",), application_root, response_root)
    actual_response = load_response_qualified_chaff(
        response_sidecar,
        workload_id="complex",
        base_manifest_path=application_path,
        expected_sidecar_schema_version=2,
        require_current_implementation=True,
    )

    surrogate_workload = root / "inputs/surrogate/workloads/complex.json"
    surrogate_sidecar = root / "inputs/surrogate/chaff-qualifications/complex.json"
    surrogate_prefix = root / "inputs/surrogate/chaff-prefix-specs/complex.json"
    for source, target, label in (
        (workload_root / "complex.json", surrogate_workload, "surrogate workload"),
        (qualification_root / "complex.json", surrogate_sidecar, "surrogate qualification"),
        (prefix_root / "complex.json", surrogate_prefix, "surrogate prefix specification"),
    ):
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"multi-origin compatibility {label} is unavailable")
        _create_or_verify_bytes(target, source.read_bytes(), f"multi-origin {label}")
    strict = load_qualified_chaff(
        surrogate_sidecar,
        workload_id="complex",
        base_manifest_path=surrogate_workload,
        prefix_spec_path=surrogate_prefix,
        require_current_implementation=True,
    )
    strict_manifest_path = root / "inputs/surrogate/chaff-manifests/complex.json"
    _create_or_verify_bytes(
        strict_manifest_path,
        canonical_bytes(strict.manifest),
        "strict surrogate qualified chaff manifest",
    )
    projection = _regression_multi_origin_projection(load_json(surrogate_workload), application)
    projected = _project_regression_chaff_manifest(
        strict.manifest,
        surrogate_sha256=sha256_file(surrogate_workload),
        application_sha256=sha256_file(application_path),
    )
    projected_chaff_path = root / "inputs/projected-chaff-manifest.json"
    _create_or_verify_bytes(
        projected_chaff_path,
        canonical_bytes(projected),
        "multi-origin projected runtime chaff manifest",
    )
    parameter_root = root / "inputs/defense-parameters"
    compatibility_walkie_talkie_source = parameter_root / "walkie-talkie-prefix-source.json"
    if walkie_talkie.is_symlink() or not walkie_talkie.is_file():
        raise ValueError("multi-origin compatibility Walkie-Talkie source is unavailable")
    _create_or_verify_bytes(
        compatibility_walkie_talkie_source,
        walkie_talkie.read_bytes(),
        "multi-origin compatibility Walkie-Talkie source",
    )
    compatibility_walkie_talkie = parameter_root / "walkie-talkie.json"
    compatibility_walkie_talkie_provenance = parameter_root / "walkie-talkie.provenance.json"
    _write_regression_multi_origin_walkie_talkie(
        compatibility_walkie_talkie_source,
        compatibility_walkie_talkie,
        compatibility_walkie_talkie_provenance,
        application_sha256=sha256_file(application_path),
        projected_manifest_sha256=sha256_file(projected_chaff_path),
    )
    defenses = _regression_multi_origin_defenses(
        compatibility_walkie_talkie,
        compatibility_walkie_talkie_provenance,
        application_sha256=sha256_file(application_path),
    )

    state_path = root / "checkpoint.json"
    if state_path.exists() or state_path.is_symlink():
        if state_path.is_symlink() or not state_path.is_file():
            raise ValueError("multi-origin compatibility checkpoint is not a regular file")
        state = load_json(state_path)
    else:
        state = {
            "schema_version": 1,
            "artifact_type": MULTI_ORIGIN_COMPATIBILITY_CHECKPOINT_TYPE,
            "accepted_attempts": {},
        }
    _validate_regression_multi_origin_checkpoint(state, require_complete=False)
    limits = capture_session.Limits(
        timeout_seconds=120,
        max_response_bytes=1_048_576,
        capture_seconds=180,
        capture_megabytes=64,
        max_attempts=3,
        per_origin_cooldown_seconds=0,
        settle_seconds=1,
    )
    samples: list[dict[str, Any]] = []
    for index, defense in enumerate(defenses):
        seed = _stable_seed("buflo-regression-multi-origin-v1", defense.name)
        mode_root = root / "attempts" / defense.name
        if mode_root.is_symlink():
            raise ValueError("multi-origin compatibility mode root cannot be a symlink")
        mode_root.mkdir(parents=True, exist_ok=True)
        accepted = state["accepted_attempts"].get(defense.name)
        evidence: dict[str, Any] | None = None
        if isinstance(accepted, str):
            candidate = root / accepted
            if candidate.resolve().is_relative_to(mode_root.resolve()):
                evidence = _regression_multi_origin_attempt_evidence(
                    candidate,
                    application_path,
                    projected_chaff_path,
                    defense,
                    seed=seed,
                )
        if evidence is None:
            for attempt_index in range(1, limits.max_attempts + 1):
                attempt = mode_root / f"attempt-{attempt_index:02d}"
                if attempt.exists() or attempt.is_symlink():
                    evidence = _regression_multi_origin_existing_attempt_evidence(
                        attempt,
                        application_path,
                        projected_chaff_path,
                        defense,
                        seed=seed,
                    )
                    if evidence is None:
                        continue
                else:
                    context = SimpleNamespace(
                        qcsd_profile=(
                            "research-1200" if defense.name in {"buflo", "cs-buflo"} else "live"
                        ),
                        request_policy="as-defined",
                        limits=limits,
                        udp_payload_ceiling=1_200,
                    )
                    try:
                        _with_kernel_tx_network_receipt(
                            regression_receipt["network"],
                            lambda: capture_session._collect_attempt(
                                attempt,
                                runtime_path,
                                None if defense.baseline else projected_chaff_path,
                                "complex",
                                defense,
                                seed,
                                context,
                                application_workload_source=(
                                    None if defense.baseline else application_path
                                ),
                            ),
                        )
                    except (
                        OSError,
                        RuntimeError,
                        subprocess.SubprocessError,
                        TypeError,
                        ValueError,
                    ) as error:
                        attempt.mkdir(parents=True, exist_ok=True)
                        _regression_multi_origin_persist_rejection(
                            attempt,
                            error,
                            stage="multi-origin-compatibility-collection",
                        )
                        continue
                    try:
                        evidence = _regression_multi_origin_attempt_evidence(
                            attempt,
                            application_path,
                            projected_chaff_path,
                            defense,
                            seed=seed,
                        )
                    except (OSError, TypeError, ValueError) as error:
                        _regression_multi_origin_persist_rejection(
                            attempt,
                            error,
                            stage="multi-origin-compatibility-eligibility",
                        )
                        continue
                if evidence is not None:
                    break
        if evidence is None:
            atomic_json(state_path, state)
            raise ValueError(
                f"multi-origin compatibility exhausted three attempts for {defense.name}"
            )
        attempt_path = Path(evidence["attempt"])
        relative_attempt = attempt_path.relative_to(root).as_posix()
        evidence["attempt"] = relative_attempt
        state["accepted_attempts"][defense.name] = relative_attempt
        atomic_json(state_path, state)
        evidence["sample_index"] = index
        samples.append(evidence)

    accepted_attempts = _validate_regression_multi_origin_checkpoint(
        state,
        require_complete=True,
    )
    attempt_ledgers = _regression_multi_origin_attempt_ledgers(
        root,
        application_path,
        projected_chaff_path,
        defenses,
        accepted_attempts,
        samples,
    )

    regression_bindings = _regression_result_bindings(result_roots)
    controlled_receipt_sha256 = _canonical_digest(dict(regression_receipt))
    if {binding["controlled_receipt_sha256"] for binding in regression_bindings} != {
        controlled_receipt_sha256
    }:
        raise ValueError(
            "multi-origin compatibility receipt differs from the frozen 18-sample campaigns"
        )
    value = {
        "schema_version": MULTI_ORIGIN_COMPATIBILITY_SCHEMA_VERSION,
        "artifact_type": MULTI_ORIGIN_COMPATIBILITY_ARTIFACT_TYPE,
        "status": "passed",
        "evidence_class": "controlled-test-only-nonformal-excluded-from-18-sample-matrix",
        "source": source_metadata(),
        "controlled_receipt": dict(regression_receipt),
        "regression_matrix_samples": 18,
        "compatibility_samples": len(samples),
        "expected_modes": list(MULTI_ORIGIN_COMPATIBILITY_MODES),
        "expected_origins": list(MULTI_ORIGIN_COMPATIBILITY_ORIGINS),
        "expected_resource_ids": [0, 1, 2, 3],
        "checkpoint": {
            "path": state_path.relative_to(root).as_posix(),
            "sha256": sha256_file(state_path),
        },
        "attempt_ledgers": attempt_ledgers,
        "inputs": {
            "application_workload": {
                "path": application_path.relative_to(root).as_posix(),
                "sha256": sha256_file(application_path),
            },
            "application_response_qualification": {
                "path": response_sidecar.relative_to(root).as_posix(),
                "sha256": sha256_file(response_sidecar),
                "derived_manifest_sha256": actual_response.manifest_sha256,
            },
            "prefix_surrogate_workload": {
                "path": surrogate_workload.relative_to(root).as_posix(),
                "sha256": sha256_file(surrogate_workload),
            },
            "prefix_surrogate_qualification": {
                "path": surrogate_sidecar.relative_to(root).as_posix(),
                "sha256": sha256_file(surrogate_sidecar),
            },
            "prefix_specification": {
                "path": surrogate_prefix.relative_to(root).as_posix(),
                "sha256": sha256_file(surrogate_prefix),
            },
            "prefix_qualified_manifest": {
                "path": strict_manifest_path.relative_to(root).as_posix(),
                "sha256": sha256_file(strict_manifest_path),
            },
            "projected_runtime_chaff_manifest": {
                "path": projected_chaff_path.relative_to(root).as_posix(),
                "sha256": sha256_file(projected_chaff_path),
            },
            "walkie_talkie_parameters": {
                "source_path": compatibility_walkie_talkie_source.relative_to(root).as_posix(),
                "source_sha256": sha256_file(compatibility_walkie_talkie_source),
                "path": compatibility_walkie_talkie.relative_to(root).as_posix(),
                "sha256": sha256_file(compatibility_walkie_talkie),
                "provenance_path": compatibility_walkie_talkie_provenance.relative_to(
                    root
                ).as_posix(),
                "provenance_sha256": sha256_file(compatibility_walkie_talkie_provenance),
            },
            "projection": projection,
            "runtime_inputs": _regression_multi_origin_runtime_inputs(defenses),
        },
        "regression_results": regression_bindings,
        "samples": samples,
        "passed": True,
    }
    _create_only_json(receipt_path, value)
    validate_regression_multi_origin_compatibility(receipt_path, result_roots)
    return receipt_path


def _regression_multi_origin_bound_path(
    root: Path,
    value: object,
    *,
    path_field: str = "path",
    sha256_field: str = "sha256",
    fields: set[str] | None = None,
    label: str,
) -> Path:
    expected_fields = fields or {path_field, sha256_field}
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ValueError(f"multi-origin compatibility {label} binding is malformed")
    relative = value.get(path_field)
    digest = value.get(sha256_field)
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise ValueError(f"multi-origin compatibility {label} binding is invalid")
    path = root / relative
    if (
        path.is_symlink()
        or not path.is_file()
        or not path.resolve().is_relative_to(root.resolve())
        or sha256_file(path) != digest
    ):
        raise ValueError(f"multi-origin compatibility {label} changed")
    return path


def _regression_multi_origin_historical_candidate_source(
    receipt_path: Path,
    source: Mapping[str, Any],
    *,
    expected_source: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Select the one sealed schema-6 proof for read-only deep revalidation."""

    current = _expected_clean_collection_source(
        expected_source,
        label="multi-origin compatibility collection image",
    )
    if dict(source) == current:
        return None
    if (
        receipt_path.parent.parent.name != "buflo-study-regression-v36"
        or sha256_file(receipt_path) != HISTORICAL_MULTI_ORIGIN_V36_RECEIPT_SHA256
        or dict(source) != HISTORICAL_MULTI_ORIGIN_V36_SOURCE
    ):
        raise ValueError(
            "multi-origin compatibility does not bind current or explicitly frozen source"
        )
    return dict(source)


def validate_regression_multi_origin_compatibility(
    receipt_path: Path,
    result_roots: Sequence[Path],
    *,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Deep-verify the excluded all-nine live two-origin correctness proof."""

    from .chaff_qualification import (
        load_qualified_chaff,
        load_response_qualified_chaff,
    )
    from .manifest import canonical_bytes, validate_research_preparation

    receipt_path = receipt_path.absolute()
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("multi-origin compatibility receipt is not a regular file")
    receipt_path = receipt_path.resolve()
    root = receipt_path.parent
    value = load_json(receipt_path)
    required = {
        "schema_version",
        "artifact_type",
        "status",
        "evidence_class",
        "source",
        "controlled_receipt",
        "regression_matrix_samples",
        "compatibility_samples",
        "expected_modes",
        "expected_origins",
        "expected_resource_ids",
        "checkpoint",
        "attempt_ledgers",
        "inputs",
        "regression_results",
        "samples",
        "passed",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value["schema_version"] != MULTI_ORIGIN_COMPATIBILITY_SCHEMA_VERSION
        or value["artifact_type"] != MULTI_ORIGIN_COMPATIBILITY_ARTIFACT_TYPE
        or value["status"] != "passed"
        or value["evidence_class"]
        != "controlled-test-only-nonformal-excluded-from-18-sample-matrix"
        or value["regression_matrix_samples"] != 18
        or value["compatibility_samples"] != 9
        or value["expected_modes"] != list(MULTI_ORIGIN_COMPATIBILITY_MODES)
        or value["expected_origins"] != list(MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
        or value["expected_resource_ids"] != [0, 1, 2, 3]
        or value["passed"] is not True
    ):
        raise ValueError("multi-origin compatibility receipt contract is invalid")
    _validate_clean_source(value["source"], label="multi-origin compatibility")
    historical_candidate_source = _regression_multi_origin_historical_candidate_source(
        receipt_path,
        value["source"],
        expected_source=_expected_collection_source,
    )
    checkpoint_path = _regression_multi_origin_bound_path(
        root,
        value["checkpoint"],
        label="checkpoint",
    )
    accepted_attempts = _validate_regression_multi_origin_checkpoint(
        load_json(checkpoint_path),
        require_complete=True,
    )
    controlled = validate_controlled_campaign_receipt(
        value["controlled_receipt"],
        _expected_collection_source=_expected_collection_source,
    )
    if controlled["stage"] != "regression" or controlled["schema_version"] not in {
        LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION,
    }:
        raise ValueError(
            "multi-origin compatibility is not bound to the current regression receipt"
        )
    if controlled["schema_version"] == TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION:
        _validate_current_regression_timing_stress(
            [controlled] * len(LOCAL_STAGE_RESULT_NAMES["regression"]),
            destination=root.parent,
            lineage=value["source"],
            expected_source=(
                value["source"]
                if historical_candidate_source is None
                else historical_candidate_source
            ),
        )
    expected_regression_results = _regression_result_bindings(result_roots)
    if value["regression_results"] != expected_regression_results:
        raise ValueError("multi-origin compatibility 18-sample result binding changed")
    controlled_receipt_sha256 = _canonical_digest(dict(value["controlled_receipt"]))
    if {binding["controlled_receipt_sha256"] for binding in expected_regression_results} != {
        controlled_receipt_sha256
    }:
        raise ValueError(
            "multi-origin compatibility receipt differs from the frozen 18-sample campaigns"
        )

    inputs = value["inputs"]
    expected_input_keys = {
        "application_workload",
        "application_response_qualification",
        "prefix_surrogate_workload",
        "prefix_surrogate_qualification",
        "prefix_specification",
        "prefix_qualified_manifest",
        "projected_runtime_chaff_manifest",
        "walkie_talkie_parameters",
        "projection",
        "runtime_inputs",
    }
    if not isinstance(inputs, Mapping) or set(inputs) != expected_input_keys:
        raise ValueError("multi-origin compatibility input inventory is invalid")
    application_path = _regression_multi_origin_bound_path(
        root, inputs["application_workload"], label="application workload"
    )
    application = load_json(application_path)
    validate_research_preparation(application, workload_id="complex")
    response_sidecar = _regression_multi_origin_bound_path(
        root,
        inputs["application_response_qualification"],
        fields={"path", "sha256", "derived_manifest_sha256"},
        label="application response qualification",
    )
    actual_response = load_response_qualified_chaff(
        response_sidecar,
        workload_id="complex",
        base_manifest_path=application_path,
        expected_sidecar_schema_version=2,
        require_current_implementation=historical_candidate_source is None,
    )
    if (
        inputs["application_response_qualification"]["derived_manifest_sha256"]
        != actual_response.manifest_sha256
    ):
        raise ValueError("multi-origin response qualification derived manifest changed")
    surrogate_workload = _regression_multi_origin_bound_path(
        root, inputs["prefix_surrogate_workload"], label="prefix surrogate workload"
    )
    surrogate_sidecar = _regression_multi_origin_bound_path(
        root,
        inputs["prefix_surrogate_qualification"],
        label="prefix surrogate qualification",
    )
    surrogate_prefix = _regression_multi_origin_bound_path(
        root, inputs["prefix_specification"], label="prefix specification"
    )
    strict_manifest_path = _regression_multi_origin_bound_path(
        root, inputs["prefix_qualified_manifest"], label="prefix-qualified manifest"
    )
    strict = load_qualified_chaff(
        surrogate_sidecar,
        workload_id="complex",
        base_manifest_path=surrogate_workload,
        prefix_spec_path=surrogate_prefix,
        require_current_implementation=historical_candidate_source is None,
    )
    if strict_manifest_path.read_bytes() != canonical_bytes(strict.manifest):
        raise ValueError("multi-origin strict prefix-qualified manifest is not derived exactly")
    expected_projection = _regression_multi_origin_projection(
        load_json(surrogate_workload), application
    )
    if inputs["projection"] != expected_projection:
        raise ValueError("multi-origin surrogate/application projection changed")
    projected_chaff_path = _regression_multi_origin_bound_path(
        root,
        inputs["projected_runtime_chaff_manifest"],
        label="projected runtime chaff manifest",
    )
    expected_projected = _project_regression_chaff_manifest(
        strict.manifest,
        surrogate_sha256=sha256_file(surrogate_workload),
        application_sha256=sha256_file(application_path),
    )
    if projected_chaff_path.read_bytes() != canonical_bytes(expected_projected):
        raise ValueError("multi-origin runtime chaff projection changed beyond source hash")

    parameter_binding = inputs["walkie_talkie_parameters"]
    parameter_fields = {
        "source_path",
        "source_sha256",
        "path",
        "sha256",
        "provenance_path",
        "provenance_sha256",
    }
    if not isinstance(parameter_binding, Mapping) or set(parameter_binding) != parameter_fields:
        raise ValueError("multi-origin Walkie-Talkie parameter binding is malformed")
    parameter_source = _regression_multi_origin_bound_path(
        root,
        parameter_binding,
        path_field="source_path",
        sha256_field="source_sha256",
        fields=parameter_fields,
        label="Walkie-Talkie source parameters",
    )
    parameter_path = _regression_multi_origin_bound_path(
        root,
        parameter_binding,
        fields=parameter_fields,
        label="Walkie-Talkie parameters",
    )
    provenance_path = _regression_multi_origin_bound_path(
        root,
        parameter_binding,
        path_field="provenance_path",
        sha256_field="provenance_sha256",
        fields=parameter_fields,
        label="Walkie-Talkie parameter provenance",
    )
    expected_parameter = _regression_multi_origin_walkie_talkie_value(
        load_json(parameter_source),
        projected_manifest_sha256=sha256_file(projected_chaff_path),
    )
    if parameter_path.read_bytes() != canonical_bytes(expected_parameter):
        raise ValueError("multi-origin Walkie-Talkie parameter projection changed")
    validate_parameter_artifact(
        parameter_path,
        provenance_path=provenance_path,
        expected_kind="walkie_talkie",
        allow_reviewed_fixture=True,
        expected_qcsd_profile="live",
        expected_udp_payload_ceiling=1_200,
        expected_workloads={"complex": sha256_file(application_path)},
    )
    defenses = _regression_multi_origin_defenses(
        parameter_path,
        provenance_path,
        application_sha256=sha256_file(application_path),
    )
    if inputs["runtime_inputs"] != _regression_multi_origin_runtime_inputs(defenses):
        raise ValueError("multi-origin compatibility runtime input identities changed")

    samples = value["samples"]
    if not isinstance(samples, list) or len(samples) != len(defenses):
        raise ValueError("multi-origin compatibility sample inventory is incomplete")
    verified_samples: list[dict[str, Any]] = []
    for index, (record, defense) in enumerate(zip(samples, defenses, strict=True)):
        if not isinstance(record, Mapping):
            raise ValueError(  # noqa: TRY004 - malformed receipt data is a ValueError.
                "multi-origin compatibility sample is not an object"
            )
        relative = record.get("attempt")
        if (
            record.get("sample_index") != index
            or record.get("mode") != defense.name
            or not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise ValueError("multi-origin compatibility sample order/binding is invalid")
        attempt = root / relative
        if not attempt.resolve().is_relative_to((root / "attempts" / defense.name).resolve()):
            raise ValueError("multi-origin compatibility attempt escapes its mode root")
        seed = _stable_seed("buflo-regression-multi-origin-v1", defense.name)
        expected = _regression_multi_origin_attempt_evidence(
            attempt,
            application_path,
            projected_chaff_path,
            defense,
            seed=seed,
            historical_candidate_source=historical_candidate_source,
        )
        expected["attempt"] = relative
        expected["sample_index"] = index
        if dict(record) != expected:
            raise ValueError("multi-origin compatibility sample receipt changed")
        verified_samples.append(expected)
    expected_ledgers = _regression_multi_origin_attempt_ledgers(
        root,
        application_path,
        projected_chaff_path,
        defenses,
        accepted_attempts,
        verified_samples,
        historical_candidate_source=historical_candidate_source,
    )
    _validate_regression_multi_origin_attempt_ledger_receipt(
        value["attempt_ledgers"],
        expected_ledgers,
    )
    return {
        "schema_version": MULTI_ORIGIN_COMPATIBILITY_SCHEMA_VERSION,
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "samples": len(verified_samples),
        "modes": [sample["mode"] for sample in verified_samples],
        "origins": list(MULTI_ORIGIN_COMPATIBILITY_ORIGINS),
        "resources_per_sample": 4,
        "attempts": sum(record["attempt_count"] for record in expected_ledgers),
        "rejected_attempts": sum(record["rejected_attempts"] for record in expected_ledgers),
        "source": dict(value["source"]),
        "excluded_from_regression_matrix": True,
        "passed": True,
    }


def _timing_stress_parameter_inputs() -> dict[str, Any]:
    """Validate the narrowly scoped tau=100 s derivative of canonical live BuFLO."""

    canonical_path = PARAMETER_FILES["buflo"][1]
    canonical_artifact = validate_parameter_artifact(
        canonical_path,
        expected_kind="buflo",
        allow_study_candidate=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )
    for path, label in (
        (TIMING_STRESS_PARAMETERS, "timing-stress parameters"),
        (TIMING_STRESS_PARAMETERS_PROVENANCE, "timing-stress provenance"),
    ):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{label} is not a regular file: {path}")
    canonical = load_json(canonical_path)
    expected_parameter = dict(canonical)
    expected_parameter["minimum_duration_us"] = TIMING_STRESS_MINIMUM_DURATION_US
    parameter = load_json(TIMING_STRESS_PARAMETERS)
    if parameter != expected_parameter:
        raise ValueError("timing-stress parameters must change only canonical minimum_duration_us")
    expected_provenance = {
        "schema_version": 4,
        "artifact_type": "qcsd-buflo-timing-stress-parameters",
        "status": "controlled-test-only",
        "production_ready": False,
        "evidence_class": "timing-stress-nonformal-excluded",
        "study_id": BUFLO_STUDY_ID,
        "defense_kind": "buflo",
        "qcsd_profile": "research-1200",
        "udp_payload_ceiling": 1_200,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "canonical_parameter": {
            "path": "../../defense-params/buflo-live.json",
            "sha256": canonical_artifact.sha256,
        },
        "parameter_file": {
            "path": TIMING_STRESS_PARAMETERS.name,
            "sha256": sha256_file(TIMING_STRESS_PARAMETERS),
        },
        "derivation": {
            "policy": (
                "canonical-live-buflo-with-only-minimum-duration-extended-for-"
                "excluded-captured-timing-stress"
            ),
            "changed_field": "minimum_duration_us",
            "canonical_value": 10_000_000,
            "stress_value": TIMING_STRESS_MINIMUM_DURATION_US,
        },
        "capture_contract": {
            "schema_version": TIMING_STRESS_SCHEMA_VERSION,
            "visits": TIMING_STRESS_VISITS,
            "max_attempts": 1,
            "authoritative_checkpoint": "experiment.json",
            "mandatory_prefix_opportunities_per_direction": (
                TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
            ),
            "maximum_opportunities_per_direction": TIMING_STRESS_MAX_EVENTS_PER_DIRECTION,
            "minimum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": (
                TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT
            ),
            "maximum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": (
                TIMING_STRESS_MAXIMUM_GUARDS_PER_VISIT
            ),
            "minimum_incoming_bytes_per_visit": (TIMING_STRESS_MINIMUM_INCOMING_BYTES_PER_VISIT),
            "maximum_incoming_bytes_per_visit": (TIMING_STRESS_MAXIMUM_INCOMING_BYTES_PER_VISIT),
            "cadence_semantics": (
                "inclusive-minimum-prefix-plus-bounded-terminal-whole-cell-drain"
            ),
            "terminal_drain_suffix": "contiguous-exact-paired-whole-cell-opportunities",
            "logical_order_evidence": "direction-target-slot-identity",
            "physical_row_order": "terminal-resolution-order-not-dispatch-order",
            "terminal_schedule_stop_policy": (
                "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
                "then_drain_already_advertised_incoming_credit"
            ),
            "strict_half_open_window_us": TIMING_STRESS_WINDOW_US,
            "catch_up": False,
            "realization_backend": "linux-etf-so-txtime-post-veth-v1",
            "runner_wakeup_schema_version": 11,
            "legacy_userspace_exact_release_projection": (
                "schema-10-compatibility-fields-retained-and-neutral"
            ),
            "kernel_tx_runner_receipt_schema_version": 2,
            "kernel_tx_evidence_schema_version": 1,
            "observer_topology_receipt_schema_version": 1,
            "physical_outgoing_observer": "router-ingress-post-client-veth-pre-netem",
            "tick_zero_physical_observation_required": True,
        },
    }
    stress_artifact = validate_parameter_artifact(
        TIMING_STRESS_PARAMETERS,
        provenance_path=TIMING_STRESS_PARAMETERS_PROVENANCE,
        expected_kind="buflo",
        allow_timing_stress=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )
    if load_json(TIMING_STRESS_PARAMETERS_PROVENANCE) != expected_provenance:
        raise ValueError("timing-stress parameter provenance is invalid")
    return {
        "canonical_parameter": _file_binding(canonical_path),
        "canonical_provenance": _file_binding(canonical_artifact.provenance_path),
        "parameter": _file_binding(TIMING_STRESS_PARAMETERS),
        "provenance": _file_binding(TIMING_STRESS_PARAMETERS_PROVENANCE),
        "input_policy": stress_artifact.input_policy,
        "derivation": expected_provenance["derivation"],
    }


def _timing_stress_defense() -> Any:
    from .capture_session import Defense

    inputs = _timing_stress_parameter_inputs()
    return Defense(
        name="buflo",
        kind="buflo",
        baseline=False,
        parameters=str(TIMING_STRESS_PARAMETERS),
        parameters_path=TIMING_STRESS_PARAMETERS,
        parameters_sha256=inputs["parameter"]["sha256"],
        parameters_provenance=str(TIMING_STRESS_PARAMETERS_PROVENANCE),
        parameters_provenance_path=TIMING_STRESS_PARAMETERS_PROVENANCE,
        parameters_provenance_sha256=inputs["provenance"]["sha256"],
        parameters_input_policy=inputs["input_policy"],
    )


def _timing_stress_checkpoint_binding(
    source: Mapping[str, Any],
    *,
    cohort_version: int,
    network_receipt: Mapping[str, Any],
    environment_binding: Mapping[str, Any],
    parameter_inputs: Mapping[str, Any],
    application_path: Path,
    runtime_path: Path,
    response_qualification_path: Path,
    response_qualification_manifest_sha256: str,
    chaff_path: Path,
) -> dict[str, Any]:
    """Bind a resumable stress launch ledger to one cohort and frozen input set."""

    return {
        "cohort_version": _cohort_version(cohort_version),
        "lab_commit": source.get("lab_commit"),
        "neqo_commit": source.get("neqo_commit"),
        "neqo_pinned_commit": source.get("neqo_pinned_commit"),
        "image_digest": source.get("image_digest"),
        "study_plan_sha256": sha256_file(STUDY_PLAN),
        "opportunity_contract_sha256": _canonical_digest(load_study_plan()["timing_stress"]),
        "canonical_parameter_sha256": parameter_inputs["canonical_parameter"]["sha256"],
        "canonical_parameter_provenance_sha256": parameter_inputs["canonical_provenance"]["sha256"],
        "parameter_sha256": parameter_inputs["parameter"]["sha256"],
        "parameter_provenance_sha256": parameter_inputs["provenance"]["sha256"],
        "network_receipt_sha256": _canonical_digest(dict(network_receipt)),
        "environment_receipt_sha256": environment_binding.get("sha256"),
        "application_workload_sha256": sha256_file(application_path),
        "runtime_workload_sha256": sha256_file(runtime_path),
        "response_qualification_sha256": sha256_file(response_qualification_path),
        "response_qualification_manifest_sha256": response_qualification_manifest_sha256,
        "qualified_chaff_manifest_sha256": sha256_file(chaff_path),
    }


def _validate_timing_stress_checkpoint(
    value: object,
    *,
    require_complete: bool,
    expected_binding: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "schema_version",
            "artifact_type",
            "campaign_binding",
            "launched_visits",
            "accepted_visits",
        }
        or value.get("schema_version") != TIMING_STRESS_SCHEMA_VERSION
        or value.get("artifact_type") != TIMING_STRESS_CHECKPOINT_TYPE
        or not isinstance(value.get("launched_visits"), Mapping)
        or not isinstance(value.get("accepted_visits"), Mapping)
    ):
        raise ValueError("timing-stress checkpoint is invalid")
    binding = value.get("campaign_binding")
    if (
        not isinstance(binding, Mapping)
        or set(binding)
        != {
            "cohort_version",
            "lab_commit",
            "neqo_commit",
            "neqo_pinned_commit",
            "image_digest",
            "study_plan_sha256",
            "opportunity_contract_sha256",
            "canonical_parameter_sha256",
            "canonical_parameter_provenance_sha256",
            "parameter_sha256",
            "parameter_provenance_sha256",
            "network_receipt_sha256",
            "environment_receipt_sha256",
            "application_workload_sha256",
            "runtime_workload_sha256",
            "response_qualification_sha256",
            "response_qualification_manifest_sha256",
            "qualified_chaff_manifest_sha256",
        }
        or type(binding.get("cohort_version")) is not int
        or binding["cohort_version"] <= 0
        or any(
            re.fullmatch(r"[0-9a-f]{40}", str(binding.get(key))) is None
            for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit")
        )
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(binding.get("image_digest"))) is None
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(binding.get(key))) is None
            for key in (
                "study_plan_sha256",
                "opportunity_contract_sha256",
                "canonical_parameter_sha256",
                "canonical_parameter_provenance_sha256",
                "parameter_sha256",
                "parameter_provenance_sha256",
                "network_receipt_sha256",
                "environment_receipt_sha256",
                "application_workload_sha256",
                "runtime_workload_sha256",
                "response_qualification_sha256",
                "response_qualification_manifest_sha256",
                "qualified_chaff_manifest_sha256",
            )
        )
        or (expected_binding is not None and dict(binding) != dict(expected_binding))
    ):
        raise ValueError("timing-stress checkpoint campaign binding is invalid")
    expected_visits = {f"visit-{visit:03d}" for visit in range(TIMING_STRESS_VISITS)}
    launched = value["launched_visits"]
    accepted = value["accepted_visits"]
    if not set(launched) <= expected_visits or not set(accepted) <= expected_visits:
        raise ValueError("timing-stress checkpoint contains an unknown visit")
    if not set(accepted) <= set(launched):
        raise ValueError("timing-stress checkpoint accepts a visit without a launch")
    if require_complete and (set(launched) != expected_visits or set(accepted) != expected_visits):
        raise ValueError("timing-stress checkpoint is incomplete")

    def normalized_visits(visits: Mapping[object, object]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for visit, relative in visits.items():
            expected = Path("attempts") / str(visit) / "attempt-01"
            if (
                not isinstance(visit, str)
                or not isinstance(relative, str)
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
                or Path(relative) != expected
            ):
                raise ValueError("timing-stress checkpoint attempt path is invalid")
            normalized[visit] = relative
        return normalized

    normalized_launched = normalized_visits(launched)
    normalized_accepted = normalized_visits(accepted)
    if any(
        normalized_launched[visit] != relative for visit, relative in normalized_accepted.items()
    ):
        raise ValueError("timing-stress checkpoint changed its physical launch")
    return normalized_accepted


def _timing_stress_reserve_launch(
    state_path: Path,
    state: dict[str, Any],
    *,
    visit_name: str,
    relative_attempt: str,
) -> bool:
    """Durably reserve the sole launch before any collection process starts."""

    _validate_timing_stress_checkpoint(state, require_complete=False)
    launched = state["launched_visits"]
    recorded = launched.get(visit_name)
    if recorded is not None:
        if recorded != relative_attempt:
            raise ValueError("timing-stress checkpoint changed its physical launch")
        return False
    launched[visit_name] = relative_attempt
    try:
        _validate_timing_stress_checkpoint(state, require_complete=False)
        atomic_json(state_path, state)
    except BaseException:
        launched.pop(visit_name, None)
        raise
    return True


def _timing_stress_attempt_rejected(attempt: Path) -> bool:
    error_path = attempt / "timing-stress-error.json"
    if error_path.exists() or error_path.is_symlink():
        return True
    result_path = attempt / "attempt.json"
    if result_path.is_file() and not result_path.is_symlink():
        try:
            result = load_json(result_path)
        except (OSError, TypeError, ValueError):
            return True
        return isinstance(result, Mapping) and result.get("success") is False
    return False


def _timing_stress_collect_or_resume(
    attempt: Path,
    collect: Callable[[], None],
    *,
    recorded_attempt: str | None = None,
    newly_reserved: bool = False,
) -> bool:
    """Use a durable reservation once; never relaunch a lost first attempt."""

    if recorded_attempt is None:
        raise ValueError("timing-stress first launch lacks a durable reservation")
    if not attempt.exists() and not attempt.is_symlink():
        if not newly_reserved:
            raise ValueError("timing-stress recorded first-launch evidence is missing and terminal")
        collect()
        return True
    if newly_reserved:
        raise ValueError("timing-stress newly reserved launch path already exists")
    if attempt.is_symlink() or not attempt.is_dir() or _timing_stress_attempt_rejected(attempt):
        raise ValueError("timing-stress first launch is rejected and terminal")
    result_path = attempt / "attempt.json"
    if result_path.is_symlink() or not result_path.is_file():
        raise ValueError("timing-stress first launch is incomplete and terminal")
    try:
        result = load_json(result_path)
    except (OSError, TypeError, ValueError) as error:
        raise ValueError("timing-stress first launch is malformed and terminal") from error
    if not isinstance(result, Mapping) or result.get("success") is not True:
        raise ValueError("timing-stress first launch is rejected and terminal")
    return False


def _timing_stress_persist_rejection(attempt: Path, error: BaseException, *, stage: str) -> None:
    """Persist the sole physical launch failure; the visit is never retried."""

    attempt.mkdir(parents=True, exist_ok=True)
    path = attempt / "timing-stress-error.json"
    if path.exists() or path.is_symlink():
        return
    value = {
        "schema_version": TIMING_STRESS_ATTEMPT_ERROR_SCHEMA_VERSION,
        "artifact_type": TIMING_STRESS_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": stage,
            "type": type(error).__name__,
            "message": str(error) or type(error).__name__,
        },
    }
    _create_only_json(path, value)


def _timing_stress_attempt_inventory(attempt: Path) -> dict[str, str]:
    files = _regression_multi_origin_raw_attempt_inventory(attempt)
    required = {
        "attempt.json",
        "captures/direct-quic.pcapng",
        "traces/direct-quic.csv",
        "neqo/run.json",
        "neqo/packets.csv",
        "neqo/events.csv",
        "neqo/schedule.csv",
    }
    if not required <= set(files):
        raise ValueError("timing-stress attempt lacks captured transport evidence")
    if "timing-stress-error.json" in files:
        raise ValueError("timing-stress attempt is durably rejected")
    return files


def _timing_stress_kernel_tx_evidence(
    attempt: Path,
    run: Mapping[str, Any],
    *,
    opportunities: int,
    network_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Deeply revalidate schema-11 sender and independent post-veth evidence."""

    from .fidelity import (
        RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
        _runner_wakeup_metrics_valid,
        _runner_wakeup_v11_legacy_buflo_metrics_neutral,
        _runner_wakeup_v7_bucket,
    )
    from .kernel_tx import (
        kernel_tx_evidence_success_valid,
        kernel_tx_receipt_sha256,
        kernel_tx_runner_receipt_success_valid,
        observer_topology_receipt_valid,
    )
    from .kernel_tx_runtime import extract_router_udp_packets

    relative_files = {
        "run": "neqo/run.json",
        "attempt": "attempt.json",
        "evidence": "diagnostics/kernel-tx-evidence.json",
        "router_capture": "diagnostics/kernel-tx-post-veth-raw.pcapng",
        "router_receipt": "diagnostics/kernel-tx-post-veth-receipt.json",
    }
    paths = {name: attempt / relative for name, relative in relative_files.items()}
    if any(path.is_symlink() or not path.is_file() for path in paths.values()):
        raise ValueError("timing-stress kernel-TX evidence inventory is incomplete or unsafe")
    if load_json(paths["run"]) != run:
        raise ValueError("timing-stress kernel-TX evidence binds a different run.json")

    wakeups = run.get("runner_wakeup_metrics")
    raw = wakeups.get("buflo_kernel_tx") if isinstance(wakeups, Mapping) else None
    if (
        not isinstance(wakeups, Mapping)
        or wakeups.get("schema_version") != 11
        or not _runner_wakeup_metrics_valid(wakeups)
        or not _runner_wakeup_v11_legacy_buflo_metrics_neutral(wakeups)
        or not isinstance(raw, Mapping)
        or raw.get("schema_version") != 2
        or not kernel_tx_runner_receipt_success_valid(raw)
    ):
        raise ValueError(
            "timing-stress requires current schema-11 kernel-TX evidence and a neutral "
            "schema-10 projection"
        )
    raw_aggregate = raw["aggregate"]
    if (
        raw_aggregate.get("job_count") != opportunities
        or raw_aggregate.get("etf_item_count") != opportunities
    ):
        raise ValueError("timing-stress kernel-TX job inventory differs from its schedule")

    result = load_json(paths["attempt"])
    topology = result.get("observer_topology_receipt") if isinstance(result, Mapping) else None
    if (
        not isinstance(result, Mapping)
        or result.get("observer_topology_required") is not True
        or result.get("observer_topology_valid") is not True
        or not isinstance(topology, Mapping)
        or not observer_topology_receipt_valid(
            topology,
            expected_image_digest=network_receipt.get("image_digest"),
        )
        or topology.get("network_receipt") != dict(network_receipt)
        or result.get("kernel_tx_evidence_required") is not True
        or result.get("kernel_tx_evidence_path") != relative_files["evidence"]
        or result.get("kernel_tx_evidence_sha256") != sha256_file(paths["evidence"])
        or result.get("kernel_tx_evidence_valid") is not True
        or result.get("kernel_tx_evidence_error") is not None
    ):
        raise ValueError("timing-stress attempt lacks canonical observer/kernel-TX bindings")

    evidence = load_json(paths["evidence"])
    router_receipt = load_json(paths["router_receipt"])
    router_packets = extract_router_udp_packets(paths["router_capture"])
    if not kernel_tx_evidence_success_valid(
        evidence,
        runner_receipt=raw,
        expected_run_json_sha256=sha256_file(paths["run"]),
        expected_router_capture_sha256=sha256_file(paths["router_capture"]),
        router_capture_receipt=router_receipt,
        router_packets=router_packets,
    ):
        raise ValueError("timing-stress kernel-TX sidecar failed canonical validation")
    if (
        evidence.get("controlled_network_receipt") != dict(network_receipt)
        or evidence.get("controlled_network_receipt_sha256")
        != topology.get("network_receipt_sha256")
        or evidence.get("controlled_observer_binding") != topology.get("observer_binding")
    ):
        raise ValueError("timing-stress kernel-TX sidecar substituted its observer topology")

    exact_release_lateness: list[int] = []
    guarded_release_lateness: list[int] = []
    reconciliations = evidence["reconciliations"]
    reconciliation_index = 0
    for job in raw["jobs"]:
        for item in job["items"]:
            reconciliation = reconciliations[reconciliation_index]
            reconciliation_index += 1
            if item["role"] != "exact-outgoing":
                continue
            lateness = reconciliation["capture_tai_upper_ns"] - job["release_tai_ns"]
            if not 0 <= lateness < TIMING_STRESS_WINDOW_US * 1_000:
                raise ValueError(
                    "timing-stress post-veth exact release missed its half-open window"
                )
            exact_release_lateness.append(lateness)
            if job["tick"] > 0:
                guarded_release_lateness.append(lateness)
    guarded_releases = opportunities - 1
    if (
        reconciliation_index != len(reconciliations)
        or len(exact_release_lateness) != opportunities
        or len(guarded_release_lateness) != guarded_releases
    ):
        raise ValueError("timing-stress exact-release reconciliation inventory is incomplete")
    histogram_counts = [0] * (len(RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS) + 1)
    for lateness in guarded_release_lateness:
        histogram_counts[_runner_wakeup_v7_bucket(lateness)] += 1

    evidence_aggregate = evidence["aggregate"]
    return {
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 11,
        "legacy_userspace_exact_release_projection": {
            "schema_version": 10,
            "neutral": True,
        },
        "runner_receipt_schema_version": raw["schema_version"],
        "evidence_schema_version": evidence["schema_version"],
        "observer_topology_schema_version": topology["schema_version"],
        "job_count": raw_aggregate["job_count"],
        "item_count": raw_aggregate["item_count"],
        "etf_item_count": raw_aggregate["etf_item_count"],
        "ordered_item_count": raw_aggregate["ordered_item_count"],
        "captured_credit_identity_count": raw_aggregate["captured_credit_identity_count"],
        "matched_item_count": evidence_aggregate["matched_item_count"],
        "runner_failed_item_count": raw_aggregate["failed_item_count"],
        "runner_unresolved_item_count": raw_aggregate["unresolved_item_count"],
        "evidence_unresolved_item_count": evidence_aggregate["unresolved_item_count"],
        "qdisc_drop_count": evidence_aggregate["qdisc_drop_count"],
        "qdisc_overlimit_count": evidence_aggregate["qdisc_overlimit_count"],
        "qdisc_requeue_count": evidence_aggregate["qdisc_requeue_count"],
        "capture_drop_count": evidence_aggregate["capture_drop_count"],
        "max_tx_software_lateness_ns": raw_aggregate["max_tx_software_lateness_ns"],
        "max_tx_to_capture_delta_ns": evidence_aggregate["max_tx_to_capture_delta_ns"],
        "max_post_veth_outgoing_release_lateness_ns": max(exact_release_lateness, default=0),
        "kernel_timed_release_lateness_histogram_after_tick_zero": {
            "upper_bounds_nanoseconds": list(RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS),
            "counts": histogram_counts,
        },
        "runner_receipt_sha256": kernel_tx_receipt_sha256(raw),
        "evidence_sha256": sha256_file(paths["evidence"]),
        "router_capture_sha256": sha256_file(paths["router_capture"]),
        "router_receipt_sha256": sha256_file(paths["router_receipt"]),
        "network_receipt_sha256": topology["network_receipt_sha256"],
    }


def _timing_stress_schedule_evidence(
    attempt: Path,
    run: Mapping[str, Any],
    *,
    network_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute exact opportunity, kernel-release, cadence, size, and lateness counts."""

    import csv

    from .fidelity import (
        SCHEDULE_PREFIX_FIELDS,
        SCHEDULE_QCSD_FIELDS,
        _csv_uint,
        _schedule_realization_metrics,
        buflo_terminal_diagnostics_valid,
    )

    schedule_path = attempt / "neqo/schedule.csv"
    if schedule_path.is_symlink() or not schedule_path.is_file():
        raise ValueError("timing-stress schedule is not a regular file")
    with schedule_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fields = tuple(reader.fieldnames or ())
    if fields != SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS:
        raise ValueError("timing-stress schedule lacks current typed outcome columns")
    by_direction: dict[str, dict[int, Mapping[str, str]]] = {
        "outgoing": {},
        "incoming": {},
    }
    outgoing_lateness: list[int] = []
    incoming_advertisement_delays: list[int] = []
    observed_slots: list[int] = []
    for row in rows:
        try:
            direction = row["direction"]
            target = _csv_uint(row, "target_time_us")
            size = _csv_uint(row, "size")
            _csv_uint(row, "connection")
            slot = _csv_uint(row, "slot_id")
            terminal = _csv_uint(row, "terminal_defense_elapsed_us")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("timing-stress schedule contains a malformed row") from error
        if direction not in by_direction or target in by_direction[direction]:
            raise ValueError("timing-stress schedule direction/target inventory is invalid")
        tick = target // TIMING_STRESS_INTERVAL_US
        expected_slot = 2 * tick + (1 if direction == "incoming" else 0)
        if (
            target % TIMING_STRESS_INTERVAL_US != 0
            or size != TIMING_STRESS_PACKET_SIZE
            or slot != expected_slot
            or row["satisfaction"] != "satisfied"
            or row["miss_reason"]
            or row["qcsd_outcome_schema_version"] != "3"
            or row["send_policy"] != "exact"
            or row["desired_udp_bytes"] != str(TIMING_STRESS_PACKET_SIZE)
            or row["congestion_reason"]
        ):
            raise ValueError("timing-stress schedule violates exact no-catch-up ordering")
        observed_slots.append(slot)
        if direction == "outgoing":
            lateness = terminal - target
            if (
                row["observed_size"] != str(TIMING_STRESS_PACKET_SIZE)
                or row["observed_udp_bytes"] != str(TIMING_STRESS_PACKET_SIZE)
                or not 0 <= lateness < TIMING_STRESS_WINDOW_US
            ):
                raise ValueError("timing-stress outgoing release missed its half-open window")
            outgoing_lateness.append(lateness)
        else:
            try:
                advertised = _csv_uint(row, "credit_advertised_at_us")
                advertisement_delay = _csv_uint(row, "credit_advertisement_delay_us")
                consumed = _csv_uint(row, "credit_consumed_at_us")
                consumption_delay = _csv_uint(row, "credit_consumption_delay_us")
                action = _csv_uint(row, "action_time_us")
            except (TypeError, ValueError) as error:
                raise ValueError(
                    "timing-stress incoming opportunity lacks exact credit evidence"
                ) from error
            if (
                row["observed_size"]
                or row["observed_udp_bytes"]
                or advertised - action != advertisement_delay
                or consumed - action != consumption_delay
                or consumed < advertised
                or not 0 <= advertisement_delay < TIMING_STRESS_WINDOW_US
            ):
                raise ValueError(
                    "timing-stress incoming credit was late, incomplete, or mismatched"
                )
            incoming_advertisement_delays.append(advertisement_delay)
        by_direction[direction][target] = row
    outgoing_targets = sorted(by_direction["outgoing"])
    incoming_targets = sorted(by_direction["incoming"])
    opportunities = len(outgoing_targets)
    if (
        outgoing_targets != incoming_targets
        or not TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
        <= opportunities
        <= TIMING_STRESS_MAX_EVENTS_PER_DIRECTION
    ):
        raise ValueError(
            "timing-stress schedule does not contain equal bounded directional inventories"
        )
    expected_targets = list(
        range(0, opportunities * TIMING_STRESS_INTERVAL_US, TIMING_STRESS_INTERVAL_US)
    )
    if outgoing_targets != expected_targets:
        raise ValueError(
            "timing-stress schedule is not the exact inclusive minimum cadence plus "
            "a contiguous terminal-drain suffix"
        )
    expected_events = opportunities * 2
    expected_slots = list(range(expected_events))
    if sorted(observed_slots) != expected_slots or len(set(observed_slots)) != expected_events:
        raise ValueError("timing-stress logical outgoing-before-incoming slot inventory is invalid")
    terminal_resolution_row_reorderings = sum(
        observed != expected for expected, observed in enumerate(observed_slots)
    )
    guarded_releases = opportunities - 1
    incoming_bytes = opportunities * TIMING_STRESS_PACKET_SIZE
    terminal_drain_opportunities = (
        opportunities - TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
    )

    metrics = _schedule_realization_metrics(attempt)
    if (
        metrics.get("scheduled_events") != expected_events
        or metrics.get("scheduled_outgoing_events") != opportunities
        or metrics.get("scheduled_incoming_events") != opportunities
        or metrics.get("satisfied_events") != expected_events
        or metrics.get("terminal_satisfactions") != {"satisfied": expected_events}
        or metrics.get("missed_events") != 0
        or metrics.get("outgoing_size_mismatch_events") != 0
        or metrics.get("catch_up_events") != 0
        or metrics.get("duplicate_terminal_slots") != 0
        or metrics.get("invalid_terminal_rows") != 0
        or metrics.get("invalid_typed_outcome_rows") != 0
        or metrics.get("incoming_credit_advertised_events") != opportunities
        or metrics.get("incoming_credit_consumed_events") != opportunities
        or metrics.get("incoming_credit_missing_events") != 0
        or metrics.get("incoming_credit_consumption_missing_events") != 0
        or metrics.get("invalid_credit_advertisement_events") != 0
        or metrics.get("invalid_credit_consumption_events") != 0
    ):
        raise ValueError("timing-stress aggregate schedule fidelity is invalid")

    kernel_tx = _timing_stress_kernel_tx_evidence(
        attempt,
        run,
        opportunities=opportunities,
        network_receipt=network_receipt,
    )

    diagnostics = run.get("defense_diagnostics")
    summary = run.get("buflo_summary")
    zero_diagnostics = (
        "buflo_partial_outgoing_cells",
        "buflo_suppressed_outgoing_cells",
        "buflo_missed_outgoing_cells",
        "buflo_missed_incoming_cells",
        "buflo_outgoing_unresolved_cells",
        "buflo_incoming_unresolved_cells",
        "buflo_catch_up_outgoing_cells",
        "buflo_catch_up_incoming_cells",
    )
    if (
        not isinstance(diagnostics, Mapping)
        or not isinstance(summary, Mapping)
        or summary.get("diagnostics") != diagnostics
        or not buflo_terminal_diagnostics_valid(diagnostics, require_current=True)
        or summary.get("schema_version") != 4
        or summary.get("kind") != "buflo"
        or summary.get("implementation_scope") != "client_only_quic"
        or summary.get("paper_equivalent") is not False
        or summary.get("terminal_schedule_stop_policy")
        != (
            "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
            "then_drain_already_advertised_incoming_credit"
        )
        or summary.get("terminal_subcell_policy")
        != "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
        or any(diagnostics.get(key) != 0 for key in zero_diagnostics)
        or diagnostics.get("buflo_event_guard_triggered") is not False
        or diagnostics.get("buflo_application_complete") is not True
        or diagnostics.get("buflo_minimum_duration_reached") is not True
        or diagnostics.get("buflo_egress_backlog_pending") is not False
        or diagnostics.get("buflo_scheduled_outgoing_cells") != opportunities
        or diagnostics.get("buflo_scheduled_incoming_cells") != opportunities
        or diagnostics.get("buflo_full_outgoing_cells") != opportunities
        or diagnostics.get("scheduled_incoming_requested_bytes") != incoming_bytes
        or diagnostics.get("scheduled_incoming_advertised_bytes") != incoming_bytes
        or diagnostics.get("scheduled_incoming_consumed_bytes") != incoming_bytes
        or diagnostics.get("scheduled_incoming_retired_bytes") != 0
        or diagnostics.get("scheduled_incoming_unresolved_bytes") != 0
    ):
        raise ValueError("timing-stress BuFLO terminal diagnostics are invalid")
    integer_terminal_fields = (
        "buflo_schedule_stop_latched_at_us",
        "buflo_schedule_stop_available_bytes",
        "buflo_schedule_stop_required_bytes",
        "buflo_schedule_stop_scheduled_incoming_cells",
        "buflo_schedule_stop_scheduled_outgoing_cells",
        "buflo_schedule_stop_terminal_incoming_cells",
        "buflo_schedule_stop_terminal_outgoing_cells",
        "buflo_terminal_subcell_latched_at_us",
        "buflo_terminal_subcell_open_streams_at_latch",
        "buflo_terminal_subcell_parser_lease_bytes_at_latch",
        "buflo_terminal_subcell_pending_parser_boundaries_at_latch",
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch",
        "buflo_terminal_subcell_pending_request_cancellations",
        "buflo_terminal_subcell_stream_cancellations",
        "buflo_terminal_subcell_exact_capacity_bytes_cancelled",
    )
    if any(type(diagnostics.get(key)) is not int for key in integer_terminal_fields):
        raise ValueError("timing-stress BuFLO terminal drain evidence is malformed")
    last_target = expected_targets[-1]
    stop_at = diagnostics["buflo_schedule_stop_latched_at_us"]
    stop_available = diagnostics["buflo_schedule_stop_available_bytes"]
    stop_required = diagnostics["buflo_schedule_stop_required_bytes"]
    stop_terminal_incoming = diagnostics["buflo_schedule_stop_terminal_incoming_cells"]
    stop_terminal_outgoing = diagnostics["buflo_schedule_stop_terminal_outgoing_cells"]
    terminal_at = diagnostics["buflo_terminal_subcell_latched_at_us"]
    open_streams = diagnostics["buflo_terminal_subcell_open_streams_at_latch"]
    cancelled_streams = diagnostics["buflo_terminal_subcell_stream_cancellations"]
    cancelled_bytes = diagnostics["buflo_terminal_subcell_exact_capacity_bytes_cancelled"]
    if (
        diagnostics.get("buflo_schedule_stop_latched") is not True
        or stop_required != TIMING_STRESS_PACKET_SIZE
        or not 0 <= stop_available < stop_required
        or diagnostics["buflo_schedule_stop_scheduled_outgoing_cells"] != opportunities
        or diagnostics["buflo_schedule_stop_scheduled_incoming_cells"] != opportunities
        or not 0 <= stop_terminal_incoming <= opportunities
        or not 0 <= stop_terminal_outgoing <= opportunities
        or not last_target <= stop_at < last_target + TIMING_STRESS_WINDOW_US
        or diagnostics.get("buflo_terminal_subcell_latched") is not True
        or terminal_at < stop_at
        or open_streams < 0
        or cancelled_streams != open_streams
        or not 0 <= cancelled_bytes < TIMING_STRESS_PACKET_SIZE
        or diagnostics["buflo_terminal_subcell_parser_lease_bytes_at_latch"] != 0
        or diagnostics["buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"] != 0
        or diagnostics["buflo_terminal_subcell_pending_request_cancellations"] != 0
    ):
        raise ValueError("timing-stress BuFLO terminal drain evidence is invalid")
    return {
        "contract_schema_version": TIMING_STRESS_SCHEMA_VERSION,
        "cadence": {
            "interval_us": TIMING_STRESS_INTERVAL_US,
            "minimum_duration_us": TIMING_STRESS_MINIMUM_DURATION_US,
            "mandatory_prefix_opportunities_per_direction": (
                TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
            ),
            "terminal_drain_opportunities_per_direction": terminal_drain_opportunities,
            "last_target_time_us": last_target,
            "logical_slot_inventory": expected_events,
            "terminal_resolution_row_reorderings": terminal_resolution_row_reorderings,
        },
        "scheduled_outgoing_opportunities": opportunities,
        "scheduled_incoming_opportunities": opportunities,
        "directional_events": expected_events,
        "full_outgoing_cells": opportunities,
        "incoming_credit_bytes": {
            "requested": incoming_bytes,
            "advertised": incoming_bytes,
            "consumed": incoming_bytes,
            "retired": 0,
            "unresolved": 0,
        },
        "mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero": (
            TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT
        ),
        "terminal_drain_kernel_timed_outgoing_releases_after_tick_zero": (
            guarded_releases - TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT
        ),
        "kernel_timed_outgoing_releases_after_tick_zero": guarded_releases,
        "release_outcomes": {
            "tick_zero_observed": 1,
            "kernel_timed_after_tick_zero": guarded_releases,
            "post_veth_matched": opportunities,
            "failed": 0,
        },
        "max_schedule_outgoing_terminal_lateness_us": max(outgoing_lateness, default=0),
        "max_incoming_credit_advertisement_delay_us": max(incoming_advertisement_delays, default=0),
        "strict_half_open_window_us": TIMING_STRESS_WINDOW_US,
        "realization_backend": kernel_tx["realization_backend"],
        "runner_wakeup_schema_version": kernel_tx["runner_wakeup_schema_version"],
        "legacy_userspace_exact_release_projection": deepcopy(
            kernel_tx["legacy_userspace_exact_release_projection"]
        ),
        "kernel_tx": kernel_tx,
        "kernel_timed_release_lateness_histogram_after_tick_zero": deepcopy(
            kernel_tx["kernel_timed_release_lateness_histogram_after_tick_zero"]
        ),
        "zero_failure_diagnostics": {key: diagnostics[key] for key in zero_diagnostics},
        "terminal_schedule_stop": {
            "policy": summary["terminal_schedule_stop_policy"],
            "latched_at_us": stop_at,
            "available_bytes": stop_available,
            "required_bytes": stop_required,
            "scheduled_incoming_cells": opportunities,
            "scheduled_outgoing_cells": opportunities,
            "terminal_incoming_cells_at_stop": stop_terminal_incoming,
            "terminal_outgoing_cells_at_stop": stop_terminal_outgoing,
            "drained_incoming_cells_after_stop": opportunities - stop_terminal_incoming,
        },
        "terminal_subcell_drain": {
            "policy": summary["terminal_subcell_policy"],
            "latched_at_us": terminal_at,
            "open_streams_at_latch": open_streams,
            "parser_lease_bytes_at_latch": 0,
            "pending_parser_boundaries_at_latch": diagnostics[
                "buflo_terminal_subcell_pending_parser_boundaries_at_latch"
            ],
            "pending_application_parser_boundaries_at_latch": 0,
            "pending_request_cancellations": 0,
            "stream_cancellations": cancelled_streams,
            "exact_capacity_bytes_cancelled": cancelled_bytes,
        },
        "passed": True,
    }


def _timing_stress_environment_input(
    root: Path, source: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    encoded = os.environ.get("QCSD_STUDY_ENVIRONMENT_B64")
    if not encoded:
        raise ValueError("timing-stress capture requires the host Docker environment receipt")
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("timing-stress Docker environment receipt is malformed") from error
    validated = validate_study_environment_receipt(
        value,
        expected_image_digest=source.get("image_digest"),
    )
    path = root / "inputs/study-environment.json"
    _create_or_verify_bytes(path, raw, "timing-stress Docker environment")
    return _file_binding(path), validated


def _timing_stress_attempt_evidence(
    attempt: Path,
    *,
    root: Path,
    application_path: Path,
    runtime_path: Path,
    chaff_path: Path,
    defense: Any,
    visit: int,
    network_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    from types import SimpleNamespace

    from .capture_session import _runner_result_complete, _validate_run_binding
    from .manifest import runtime_manifest
    from .orchestrator import _intrinsic_fidelity_failure
    from .process_scheduler import capture_scheduler_runtime_evidence_valid

    if _timing_stress_attempt_rejected(attempt):
        raise ValueError("timing-stress visit has a durable rejected first launch")
    application = load_json(application_path)
    if load_json(runtime_path) != runtime_manifest(application):
        raise ValueError("timing-stress runtime workload binding changed")
    result_path = attempt / "attempt.json"
    run_path = attempt / "neqo/run.json"
    if (
        result_path.is_symlink()
        or run_path.is_symlink()
        or not result_path.is_file()
        or not run_path.is_file()
    ):
        raise ValueError("timing-stress attempt lacks regular terminal receipts")
    result = load_json(result_path)
    run = load_json(run_path)
    expected_ids = {resource["id"] for resource in application["resources"]}
    scheduler_relative = result.get("scheduler_runtime_evidence_path")
    scheduler_path = (
        attempt / scheduler_relative
        if isinstance(scheduler_relative, str)
        and not Path(scheduler_relative).is_absolute()
        and ".." not in Path(scheduler_relative).parts
        else None
    )
    scheduler_evidence = result.get("scheduler_runtime_evidence")
    if (
        not isinstance(result, dict)
        or result.get("success") is not True
        or result.get("runner_complete") is not True
        or result.get("runner_binding_valid") is not True
        or result.get("endpoint_count") != 2
        or result.get("expected_endpoint_count") != 2
        or result.get("endpoint_count_valid") is not True
        or result.get("process_scheduler_required") is not True
        or result.get("process_scheduler_valid") is not True
        or result.get("scheduler_runtime_evidence_valid") is not True
        or scheduler_path is None
        or scheduler_path.is_symlink()
        or not scheduler_path.is_file()
        or result.get("scheduler_runtime_evidence_sha256") != sha256_file(scheduler_path)
        or load_json(scheduler_path) != scheduler_evidence
        or not capture_scheduler_runtime_evidence_valid(scheduler_evidence)
        or not _runner_result_complete(run, expected_ids)
    ):
        raise ValueError(
            "timing-stress attempt is not captured, scheduler-valid, and runner-complete"
        )
    limits = SimpleNamespace(
        timeout_seconds=120,
        max_response_bytes=1_048_576,
        capture_seconds=180,
        capture_megabytes=64,
        max_attempts=1,
        per_origin_cooldown_seconds=0,
        settle_seconds=1,
    )
    context = SimpleNamespace(
        qcsd_profile="research-1200",
        request_policy="as-defined",
        limits=limits,
        udp_payload_ceiling=1_200,
    )
    seed = _stable_seed(TIMING_STRESS_SEED_NAMESPACE, f"visit-{visit:03d}")
    _validate_run_binding(
        run,
        manifest=runtime_path,
        chaff_manifest=chaff_path,
        application_workload_source=application_path,
        workload_id="complex",
        defense=defense,
        seed=seed,
        context=context,
    )
    sample = {
        "sample_id": f"timing-stress-visit-{visit:03d}",
        "defense": "buflo",
        "runtime_kind": "buflo",
    }
    fidelity_failure = _intrinsic_fidelity_failure(sample, result, attempt)
    if fidelity_failure is not None:
        raise ValueError(
            f"timing-stress attempt failed strict ordinary fidelity eligibility: {fidelity_failure}"
        )
    timing = _timing_stress_schedule_evidence(
        attempt,
        run,
        network_receipt=network_receipt,
    )
    identity = _regression_multi_origin_run_identity(run, application, mode="buflo")
    files = _timing_stress_attempt_inventory(attempt)
    return {
        "visit": visit,
        "seed": seed,
        "attempt": attempt.relative_to(root).as_posix(),
        "attempt_index": 1,
        "files": files,
        "files_sha256": _canonical_digest(files),
        "scheduler_runtime_evidence_sha256": sha256_file(scheduler_path),
        "identity": identity,
        "timing": timing,
        "fidelity_eligible": True,
        "passed": True,
    }


def _timing_stress_attempt_ledgers(
    root: Path,
    *,
    application_path: Path,
    runtime_path: Path,
    chaff_path: Path,
    defense: Any,
    accepted_visits: Mapping[str, str],
    samples: Sequence[Mapping[str, Any]],
    network_receipt: Mapping[str, Any],
) -> list[dict[str, Any]]:
    attempts_root = root / "attempts"
    expected_visit_names = [f"visit-{visit:03d}" for visit in range(TIMING_STRESS_VISITS)]
    if attempts_root.is_symlink() or not attempts_root.is_dir():
        raise ValueError("timing-stress attempts root is invalid")
    actual_visit_names = sorted(path.name for path in attempts_root.iterdir())
    if actual_visit_names != expected_visit_names or any(
        path.is_symlink() or not path.is_dir() for path in attempts_root.iterdir()
    ):
        raise ValueError("timing-stress visit directory inventory is not exact")
    if set(accepted_visits) != set(expected_visit_names) or len(samples) != TIMING_STRESS_VISITS:
        raise ValueError("timing-stress accepted visit inventory is incomplete")
    ledgers: list[dict[str, Any]] = []
    for visit, record in enumerate(samples):
        visit_name = expected_visit_names[visit]
        visit_root = attempts_root / visit_name
        children = list(visit_root.iterdir())
        attempt = visit_root / "attempt-01"
        if (
            len(children) != 1
            or children[0] != attempt
            or attempt.is_symlink()
            or not attempt.is_dir()
            or _timing_stress_attempt_rejected(attempt)
        ):
            raise ValueError("timing-stress visit is not one accepted physical launch")
        expected = _timing_stress_attempt_evidence(
            attempt,
            root=root,
            application_path=application_path,
            runtime_path=runtime_path,
            chaff_path=chaff_path,
            defense=defense,
            visit=visit,
            network_receipt=network_receipt,
        )
        if dict(record) != expected or accepted_visits[visit_name] != expected["attempt"]:
            raise ValueError("timing-stress accepted visit binding changed")
        ledgers.append(
            {
                "visit": visit,
                "attempt_count": 1,
                "accepted_attempt": expected["attempt"],
                "rejected_attempts": 0,
                "files_sha256": expected["files_sha256"],
            }
        )
    return ledgers


def _timing_stress_v2_aggregate(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Reconstruct the frozen schema-2 user-space timing-stress aggregate."""
    timings = [sample.get("timing") for sample in samples]
    if len(timings) != TIMING_STRESS_VISITS or any(
        not isinstance(timing, Mapping) for timing in timings
    ):
        raise ValueError("timing-stress timing evidence is incomplete")
    typed_timings = [dict(timing) for timing in timings if isinstance(timing, Mapping)]
    if any(
        timing.get("contract_schema_version") != PREVIOUS_TIMING_STRESS_SCHEMA_VERSION
        for timing in typed_timings
    ):
        raise ValueError("timing-stress sample contract is not frozen schema 2")
    observed_total_guards = sum(
        int(timing["guarded_outgoing_releases"]) for timing in typed_timings
    )
    dispatch_histograms = [timing["dispatch_lateness_histogram"] for timing in typed_timings]
    gap_histograms = [timing["active_spin_gap_histogram"] for timing in typed_timings]
    counter_receipts = [timing["active_wait_counter"] for timing in typed_timings]
    [first_counter, *remaining_counters] = counter_receipts
    counter_source = first_counter["source"]
    counter_frequency_hz = first_counter["frequency_hz"]
    if any(
        counter["source"] != counter_source or counter["frequency_hz"] != counter_frequency_hz
        for counter in remaining_counters
    ):
        raise ValueError("timing-stress predictive counter changed between visits")

    def aggregate_histograms(values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        [first, *rest] = values
        bounds = first.get("upper_bounds_nanoseconds")
        counts = first.get("counts")
        if not isinstance(bounds, list) or not isinstance(counts, list):
            raise TypeError("timing-stress histogram is malformed")
        aggregate = list(counts)
        for value in rest:
            if value.get("upper_bounds_nanoseconds") != bounds:
                raise ValueError("timing-stress histogram bounds changed between visits")
            candidate = value.get("counts")
            if not isinstance(candidate, list) or len(candidate) != len(aggregate):
                raise ValueError("timing-stress histogram bucket inventory changed")
            aggregate = [left + right for left, right in zip(aggregate, candidate, strict=True)]
        if sum(aggregate) != observed_total_guards:
            raise ValueError("timing-stress aggregate histogram does not cover every guard")
        return {"upper_bounds_nanoseconds": list(bounds), "counts": aggregate}

    return {
        "contract_schema_version": PREVIOUS_TIMING_STRESS_SCHEMA_VERSION,
        "visits": TIMING_STRESS_VISITS,
        "physical_attempts": TIMING_STRESS_VISITS,
        "rejected_attempts": 0,
        "opportunities_per_direction_by_visit": [
            int(timing["scheduled_outgoing_opportunities"]) for timing in typed_timings
        ],
        "terminal_drain_opportunities_per_direction_by_visit": [
            int(timing["cadence"]["terminal_drain_opportunities_per_direction"])
            for timing in typed_timings
        ],
        "mandatory_prefix_guarded_outgoing_releases": TIMING_STRESS_MINIMUM_TOTAL_GUARDS,
        "terminal_drain_guarded_outgoing_releases": (
            observed_total_guards - TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        ),
        "guarded_outgoing_releases": observed_total_guards,
        "guard_outcomes": {
            "entries": sum(int(timing["guard_outcomes"]["entries"]) for timing in typed_timings),
            "dispatch_ready": sum(
                int(timing["guard_outcomes"]["dispatch_ready"]) for timing in typed_timings
            ),
            "failed": sum(int(timing["guard_outcomes"]["failed"]) for timing in typed_timings),
            "typed_failures": {
                key: sum(
                    int(timing["guard_outcomes"]["typed_failures"][key]) for timing in typed_timings
                )
                for key in (
                    "invalid_counter_frequency",
                    "counter_unavailable",
                    "counter_nonmonotonic",
                    "counter_frequency_changed",
                    "counter_target_error",
                )
            },
            "last_failures": sum(
                timing["guard_outcomes"]["last_failure"] is not None for timing in typed_timings
            ),
        },
        "outgoing_opportunities": sum(
            int(timing["scheduled_outgoing_opportunities"]) for timing in typed_timings
        ),
        "incoming_opportunities": sum(
            int(timing["scheduled_incoming_opportunities"]) for timing in typed_timings
        ),
        "directional_events": sum(int(timing["directional_events"]) for timing in typed_timings),
        "full_outgoing_cells": sum(int(timing["full_outgoing_cells"]) for timing in typed_timings),
        "terminal_drain_opportunities_per_direction": sum(
            int(timing["cadence"]["terminal_drain_opportunities_per_direction"])
            for timing in typed_timings
        ),
        "minimum_last_target_time_us": min(
            int(timing["cadence"]["last_target_time_us"]) for timing in typed_timings
        ),
        "maximum_last_target_time_us": max(
            int(timing["cadence"]["last_target_time_us"]) for timing in typed_timings
        ),
        "terminal_resolution_row_reorderings": sum(
            int(timing["cadence"]["terminal_resolution_row_reorderings"])
            for timing in typed_timings
        ),
        "incoming_credit_bytes": {
            key: sum(int(timing["incoming_credit_bytes"][key]) for timing in typed_timings)
            for key in ("requested", "advertised", "consumed", "retired", "unresolved")
        },
        "max_outgoing_release_lateness_us": max(
            int(timing["max_outgoing_release_lateness_us"]) for timing in typed_timings
        ),
        "max_incoming_credit_advertisement_delay_us": max(
            int(timing["max_incoming_credit_advertisement_delay_us"]) for timing in typed_timings
        ),
        "max_guard_exit_lateness_nanoseconds": max(
            int(timing["max_guard_exit_lateness_nanoseconds"]) for timing in typed_timings
        ),
        "max_active_spin_gap_nanoseconds": max(
            int(timing["max_active_spin_gap_nanoseconds"]) for timing in typed_timings
        ),
        "active_wait_poll_source": counter_source,
        "active_wait_counter_frequency_hz": counter_frequency_hz,
        "active_wait_counter_guards": sum(
            int(timing["active_wait_counter"]["counter_guards"]) for timing in typed_timings
        ),
        "active_wait_counter_unavailable_guards": sum(
            int(timing["active_wait_counter"]["unavailable_guards"]) for timing in typed_timings
        ),
        "active_wait_counter_nonmonotonic_guards": sum(
            int(timing["active_wait_counter"]["nonmonotonic_guards"]) for timing in typed_timings
        ),
        "active_wait_counter_calibrations": sum(
            int(timing["active_wait_counter"]["calibrations"]) for timing in typed_timings
        ),
        "active_wait_instant_confirmations": sum(
            int(timing["active_wait_counter"]["instant_confirmations"]) for timing in typed_timings
        ),
        "active_wait_early_confirmation_retries": sum(
            int(timing["active_wait_counter"]["early_confirmation_retries"])
            for timing in typed_timings
        ),
        "active_wait_authoritative_watchdog_checks": sum(
            int(timing["active_wait_counter"]["authoritative_watchdog_checks"])
            for timing in typed_timings
        ),
        "active_wait_authoritative_watchdog_dispatches": sum(
            int(timing["active_wait_counter"]["authoritative_watchdog_dispatches"])
            for timing in typed_timings
        ),
        "active_wait_authoritative_watchdog_cadence_validated_guards": sum(
            int(timing["active_wait_counter"]["authoritative_watchdog_cadence_validated_guards"])
            for timing in typed_timings
        ),
        "active_wait_counter_nanoseconds": sum(
            int(timing["active_wait_counter"]["counter_nanoseconds"]) for timing in typed_timings
        ),
        "max_active_wait_counter_gap_nanoseconds": max(
            int(timing["active_wait_counter"]["max_counter_gap_nanoseconds"])
            for timing in typed_timings
        ),
        "max_counter_calibration_span_nanoseconds": max(
            int(timing["active_wait_counter"]["max_calibration_span_nanoseconds"])
            for timing in typed_timings
        ),
        "max_authoritative_sample_gap_nanoseconds": max(
            int(timing["active_wait_counter"]["max_authoritative_sample_gap_nanoseconds"])
            for timing in typed_timings
        ),
        "max_authoritative_counter_lag_nanoseconds": max(
            int(timing["active_wait_counter"]["max_authoritative_counter_lag_nanoseconds"])
            for timing in typed_timings
        ),
        "max_counter_authoritative_lead_nanoseconds": max(
            int(timing["active_wait_counter"]["max_counter_authoritative_lead_nanoseconds"])
            for timing in typed_timings
        ),
        "dispatch_lateness_histogram": aggregate_histograms(dispatch_histograms),
        "active_spin_gap_histogram": aggregate_histograms(gap_histograms),
        "zero_failure_counts": {
            "rejected_attempts": 0,
            "late_outgoing_releases": 0,
            "late_incoming_advertisements": 0,
            "partial_outgoing_cells": 0,
            "suppressed_outgoing_cells": 0,
            "missed_directional_events": 0,
            "mismatched_outgoing_cells": 0,
            "catch_up_directional_events": 0,
            "unresolved_directional_events": 0,
            "retired_incoming_bytes": 0,
            "unresolved_incoming_bytes": 0,
        },
        "observed_sensitivity": _timing_stress_sensitivity(observed_total_guards),
        "passed": True,
    }


def _validate_timing_stress_v2_aggregate(aggregate: Mapping[str, Any]) -> None:
    """Validate the frozen schema-2 user-space timing-stress aggregate."""

    guards = aggregate.get("guarded_outgoing_releases")
    outgoing = aggregate.get("outgoing_opportunities")
    incoming = aggregate.get("incoming_opportunities")
    opportunities_by_visit = aggregate.get("opportunities_per_direction_by_visit")
    drain_by_visit = aggregate.get("terminal_drain_opportunities_per_direction_by_visit")
    if type(guards) is not int or type(outgoing) is not int or type(incoming) is not int:
        raise ValueError("timing-stress aggregate counts are malformed")
    expected_guard_outcomes = {
        "entries": guards,
        "dispatch_ready": guards,
        "failed": 0,
        "typed_failures": {
            "invalid_counter_frequency": 0,
            "counter_unavailable": 0,
            "counter_nonmonotonic": 0,
            "counter_frequency_changed": 0,
            "counter_target_error": 0,
        },
        "last_failures": 0,
    }
    incoming_bytes = incoming * TIMING_STRESS_PACKET_SIZE
    if (
        aggregate.get("contract_schema_version") != PREVIOUS_TIMING_STRESS_SCHEMA_VERSION
        or not TIMING_STRESS_MINIMUM_TOTAL_GUARDS <= guards <= TIMING_STRESS_MAXIMUM_TOTAL_GUARDS
        or not isinstance(opportunities_by_visit, list)
        or len(opportunities_by_visit) != TIMING_STRESS_VISITS
        or any(
            type(value) is not int
            or not TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
            <= value
            <= TIMING_STRESS_MAX_EVENTS_PER_DIRECTION
            for value in opportunities_by_visit
        )
        or sum(opportunities_by_visit) != outgoing
        or not isinstance(drain_by_visit, list)
        or drain_by_visit
        != [
            value - TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
            for value in opportunities_by_visit
        ]
        or aggregate.get("mandatory_prefix_guarded_outgoing_releases")
        != TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        or aggregate.get("terminal_drain_guarded_outgoing_releases")
        != guards - TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        or aggregate.get("guard_outcomes") != expected_guard_outcomes
        or not TIMING_STRESS_MINIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        <= outgoing
        <= TIMING_STRESS_MAXIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        or outgoing != incoming
        or aggregate.get("directional_events") != outgoing + incoming
        or aggregate.get("full_outgoing_cells") != outgoing
        or aggregate.get("terminal_drain_opportunities_per_direction")
        != outgoing - TIMING_STRESS_MINIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        or aggregate.get("terminal_drain_opportunities_per_direction") != sum(drain_by_visit)
        or guards != outgoing - TIMING_STRESS_VISITS
        or aggregate.get("incoming_credit_bytes")
        != {
            "requested": incoming_bytes,
            "advertised": incoming_bytes,
            "consumed": incoming_bytes,
            "retired": 0,
            "unresolved": 0,
        }
        or aggregate.get("physical_attempts") != TIMING_STRESS_VISITS
        or aggregate.get("rejected_attempts") != 0
        or type(aggregate.get("terminal_resolution_row_reorderings")) is not int
        or aggregate["terminal_resolution_row_reorderings"] < 0
        or type(aggregate.get("minimum_last_target_time_us")) is not int
        or aggregate["minimum_last_target_time_us"]
        != (min(opportunities_by_visit) - 1) * TIMING_STRESS_INTERVAL_US
        or type(aggregate.get("maximum_last_target_time_us")) is not int
        or aggregate["maximum_last_target_time_us"]
        != (max(opportunities_by_visit) - 1) * TIMING_STRESS_INTERVAL_US
        or aggregate.get("active_wait_poll_source")
        != "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
        or type(aggregate.get("active_wait_counter_frequency_hz")) is not int
        or aggregate["active_wait_counter_frequency_hz"] <= 0
        or aggregate.get("active_wait_counter_guards") != guards
        or aggregate.get("active_wait_counter_unavailable_guards") != 0
        or aggregate.get("active_wait_counter_nonmonotonic_guards") != 0
        or aggregate.get("active_wait_instant_confirmations")
        != guards + aggregate.get("active_wait_early_confirmation_retries", -1)
        or aggregate.get("active_wait_counter_calibrations")
        != aggregate.get("active_wait_instant_confirmations")
        or type(aggregate.get("active_wait_authoritative_watchdog_checks")) is not int
        or aggregate["active_wait_authoritative_watchdog_checks"] <= 0
        or type(aggregate.get("active_wait_authoritative_watchdog_dispatches")) is not int
        or not 0
        <= aggregate["active_wait_authoritative_watchdog_dispatches"]
        <= aggregate["active_wait_authoritative_watchdog_checks"]
        or aggregate["active_wait_authoritative_watchdog_dispatches"] > guards
        or aggregate.get("active_wait_authoritative_watchdog_cadence_validated_guards") != guards
        or any(
            type(aggregate.get(key)) is not int or aggregate[key] < 0
            for key in (
                "max_authoritative_sample_gap_nanoseconds",
                "max_authoritative_counter_lag_nanoseconds",
                "max_counter_authoritative_lead_nanoseconds",
            )
        )
        or aggregate.get("max_active_spin_gap_nanoseconds")
        != aggregate.get("max_active_wait_counter_gap_nanoseconds")
        or aggregate.get("max_counter_calibration_span_nanoseconds", -1)
        > aggregate.get("max_active_wait_counter_gap_nanoseconds", -1)
        or aggregate.get("max_guard_exit_lateness_nanoseconds", TIMING_STRESS_WINDOW_US * 1_000)
        >= TIMING_STRESS_WINDOW_US * 1_000
        or aggregate.get("observed_sensitivity") != _timing_stress_sensitivity(guards)
        or not isinstance(aggregate.get("zero_failure_counts"), Mapping)
        or any(value != 0 for value in aggregate["zero_failure_counts"].values())
        or aggregate.get("passed") is not True
    ):
        raise ValueError("timing-stress aggregate zero-failure gate did not pass")


def _timing_stress_aggregate(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate the current kernel-timed, independently observed contract."""

    timings = [sample.get("timing") for sample in samples]
    if len(timings) != TIMING_STRESS_VISITS or any(
        not isinstance(timing, Mapping) for timing in timings
    ):
        raise ValueError("timing-stress timing evidence is incomplete")
    typed_timings = [dict(timing) for timing in timings if isinstance(timing, Mapping)]
    expected_projection = {"schema_version": 10, "neutral": True}
    kernels = [timing.get("kernel_tx") for timing in typed_timings]
    if any(
        timing.get("contract_schema_version") != TIMING_STRESS_SCHEMA_VERSION
        or timing.get("realization_backend") != "linux-etf-so-txtime-post-veth-v1"
        or timing.get("runner_wakeup_schema_version") != 11
        or timing.get("legacy_userspace_exact_release_projection") != expected_projection
        or not isinstance(kernel, Mapping)
        or kernel.get("realization_backend") != "linux-etf-so-txtime-post-veth-v1"
        or kernel.get("runner_wakeup_schema_version") != 11
        or kernel.get("legacy_userspace_exact_release_projection") != expected_projection
        or kernel.get("runner_receipt_schema_version") != 2
        or kernel.get("evidence_schema_version") != 1
        or kernel.get("observer_topology_schema_version") != 1
        for timing, kernel in zip(typed_timings, kernels, strict=True)
    ):
        raise ValueError("timing-stress sample does not use the current kernel-TX contract")
    typed_kernels = [dict(kernel) for kernel in kernels if isinstance(kernel, Mapping)]
    observed_total_releases = sum(
        int(timing["kernel_timed_outgoing_releases_after_tick_zero"]) for timing in typed_timings
    )

    def aggregate_histograms(values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        [first, *rest] = values
        bounds = first.get("upper_bounds_nanoseconds")
        counts = first.get("counts")
        if not isinstance(bounds, list) or not isinstance(counts, list):
            raise TypeError("timing-stress histogram is malformed")
        aggregate = list(counts)
        for value in rest:
            if value.get("upper_bounds_nanoseconds") != bounds:
                raise ValueError("timing-stress histogram bounds changed between visits")
            candidate = value.get("counts")
            if not isinstance(candidate, list) or len(candidate) != len(aggregate):
                raise ValueError("timing-stress histogram bucket inventory changed")
            aggregate = [left + right for left, right in zip(aggregate, candidate, strict=True)]
        if sum(aggregate) != observed_total_releases:
            raise ValueError(
                "timing-stress aggregate histogram does not cover every post-tick-zero release"
            )
        return {"upper_bounds_nanoseconds": list(bounds), "counts": aggregate}

    network_hashes = {kernel["network_receipt_sha256"] for kernel in typed_kernels}
    if len(network_hashes) != 1:
        raise ValueError("timing-stress observer network changed between visits")
    [network_receipt_sha256] = network_hashes
    release_histograms = [
        timing["kernel_timed_release_lateness_histogram_after_tick_zero"]
        for timing in typed_timings
    ]
    outgoing = sum(int(timing["scheduled_outgoing_opportunities"]) for timing in typed_timings)
    incoming = sum(int(timing["scheduled_incoming_opportunities"]) for timing in typed_timings)
    return {
        "contract_schema_version": TIMING_STRESS_SCHEMA_VERSION,
        "visits": TIMING_STRESS_VISITS,
        "physical_attempts": TIMING_STRESS_VISITS,
        "rejected_attempts": 0,
        "opportunities_per_direction_by_visit": [
            int(timing["scheduled_outgoing_opportunities"]) for timing in typed_timings
        ],
        "terminal_drain_opportunities_per_direction_by_visit": [
            int(timing["cadence"]["terminal_drain_opportunities_per_direction"])
            for timing in typed_timings
        ],
        "mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero": (
            TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        ),
        "terminal_drain_kernel_timed_outgoing_releases_after_tick_zero": (
            observed_total_releases - TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        ),
        "kernel_timed_outgoing_releases_after_tick_zero": observed_total_releases,
        "release_outcomes": {
            "tick_zero_observed": sum(
                int(timing["release_outcomes"]["tick_zero_observed"]) for timing in typed_timings
            ),
            "kernel_timed_after_tick_zero": sum(
                int(timing["release_outcomes"]["kernel_timed_after_tick_zero"])
                for timing in typed_timings
            ),
            "post_veth_matched": sum(
                int(timing["release_outcomes"]["post_veth_matched"]) for timing in typed_timings
            ),
            "failed": sum(int(timing["release_outcomes"]["failed"]) for timing in typed_timings),
        },
        "outgoing_opportunities": outgoing,
        "incoming_opportunities": incoming,
        "directional_events": sum(int(timing["directional_events"]) for timing in typed_timings),
        "full_outgoing_cells": sum(int(timing["full_outgoing_cells"]) for timing in typed_timings),
        "terminal_drain_opportunities_per_direction": sum(
            int(timing["cadence"]["terminal_drain_opportunities_per_direction"])
            for timing in typed_timings
        ),
        "minimum_last_target_time_us": min(
            int(timing["cadence"]["last_target_time_us"]) for timing in typed_timings
        ),
        "maximum_last_target_time_us": max(
            int(timing["cadence"]["last_target_time_us"]) for timing in typed_timings
        ),
        "terminal_resolution_row_reorderings": sum(
            int(timing["cadence"]["terminal_resolution_row_reorderings"])
            for timing in typed_timings
        ),
        "incoming_credit_bytes": {
            key: sum(int(timing["incoming_credit_bytes"][key]) for timing in typed_timings)
            for key in ("requested", "advertised", "consumed", "retired", "unresolved")
        },
        "max_schedule_outgoing_terminal_lateness_us": max(
            int(timing["max_schedule_outgoing_terminal_lateness_us"]) for timing in typed_timings
        ),
        "max_incoming_credit_advertisement_delay_us": max(
            int(timing["max_incoming_credit_advertisement_delay_us"]) for timing in typed_timings
        ),
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 11,
        "legacy_userspace_exact_release_projection": {
            "schema_version": 10,
            "neutral_visits": TIMING_STRESS_VISITS,
            "nonneutral_visits": 0,
        },
        "kernel_tx": {
            "runner_receipt_schema_version": 2,
            "evidence_schema_version": 1,
            "observer_topology_schema_version": 1,
            "job_count": sum(int(kernel["job_count"]) for kernel in typed_kernels),
            "item_count": sum(int(kernel["item_count"]) for kernel in typed_kernels),
            "etf_item_count": sum(int(kernel["etf_item_count"]) for kernel in typed_kernels),
            "ordered_item_count": sum(
                int(kernel["ordered_item_count"]) for kernel in typed_kernels
            ),
            "captured_credit_identity_count": sum(
                int(kernel["captured_credit_identity_count"]) for kernel in typed_kernels
            ),
            "matched_item_count": sum(
                int(kernel["matched_item_count"]) for kernel in typed_kernels
            ),
            "runner_failed_item_count": sum(
                int(kernel["runner_failed_item_count"]) for kernel in typed_kernels
            ),
            "runner_unresolved_item_count": sum(
                int(kernel["runner_unresolved_item_count"]) for kernel in typed_kernels
            ),
            "evidence_unresolved_item_count": sum(
                int(kernel["evidence_unresolved_item_count"]) for kernel in typed_kernels
            ),
            "qdisc_drop_count": sum(int(kernel["qdisc_drop_count"]) for kernel in typed_kernels),
            "qdisc_overlimit_count": sum(
                int(kernel["qdisc_overlimit_count"]) for kernel in typed_kernels
            ),
            "qdisc_requeue_count": sum(
                int(kernel["qdisc_requeue_count"]) for kernel in typed_kernels
            ),
            "capture_drop_count": sum(
                int(kernel["capture_drop_count"]) for kernel in typed_kernels
            ),
            "max_tx_software_lateness_ns": max(
                int(kernel["max_tx_software_lateness_ns"]) for kernel in typed_kernels
            ),
            "max_tx_to_capture_delta_ns": max(
                int(kernel["max_tx_to_capture_delta_ns"]) for kernel in typed_kernels
            ),
            "max_post_veth_outgoing_release_lateness_ns": max(
                int(kernel["max_post_veth_outgoing_release_lateness_ns"])
                for kernel in typed_kernels
            ),
            "network_receipt_sha256": network_receipt_sha256,
        },
        "kernel_timed_release_lateness_histogram_after_tick_zero": (
            aggregate_histograms(release_histograms)
        ),
        "zero_failure_counts": {
            "rejected_attempts": 0,
            "late_schedule_outgoing_terminals": 0,
            "late_post_veth_outgoing_releases": 0,
            "late_incoming_advertisements": 0,
            "partial_outgoing_cells": 0,
            "suppressed_outgoing_cells": 0,
            "missed_directional_events": 0,
            "mismatched_outgoing_cells": 0,
            "catch_up_directional_events": 0,
            "unresolved_directional_events": 0,
            "retired_incoming_bytes": 0,
            "unresolved_incoming_bytes": 0,
            "runner_failed_kernel_tx_items": 0,
            "runner_unresolved_kernel_tx_items": 0,
            "evidence_unresolved_kernel_tx_items": 0,
            "qdisc_drops": 0,
            "qdisc_overlimits": 0,
            "qdisc_requeues": 0,
            "capture_drops": 0,
        },
        "observed_sensitivity": _timing_stress_kernel_sensitivity(observed_total_releases),
        "passed": True,
    }


def _validate_timing_stress_aggregate(aggregate: Mapping[str, Any]) -> None:
    """Require every current ETF release and post-veth observation to pass."""

    from .fidelity import RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS

    top_level_keys = {
        "contract_schema_version",
        "visits",
        "physical_attempts",
        "rejected_attempts",
        "opportunities_per_direction_by_visit",
        "terminal_drain_opportunities_per_direction_by_visit",
        "mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero",
        "terminal_drain_kernel_timed_outgoing_releases_after_tick_zero",
        "kernel_timed_outgoing_releases_after_tick_zero",
        "release_outcomes",
        "outgoing_opportunities",
        "incoming_opportunities",
        "directional_events",
        "full_outgoing_cells",
        "terminal_drain_opportunities_per_direction",
        "minimum_last_target_time_us",
        "maximum_last_target_time_us",
        "terminal_resolution_row_reorderings",
        "incoming_credit_bytes",
        "max_schedule_outgoing_terminal_lateness_us",
        "max_incoming_credit_advertisement_delay_us",
        "realization_backend",
        "runner_wakeup_schema_version",
        "legacy_userspace_exact_release_projection",
        "kernel_tx",
        "kernel_timed_release_lateness_histogram_after_tick_zero",
        "zero_failure_counts",
        "observed_sensitivity",
        "passed",
    }
    kernel_keys = {
        "runner_receipt_schema_version",
        "evidence_schema_version",
        "observer_topology_schema_version",
        "job_count",
        "item_count",
        "etf_item_count",
        "ordered_item_count",
        "captured_credit_identity_count",
        "matched_item_count",
        "runner_failed_item_count",
        "runner_unresolved_item_count",
        "evidence_unresolved_item_count",
        "qdisc_drop_count",
        "qdisc_overlimit_count",
        "qdisc_requeue_count",
        "capture_drop_count",
        "max_tx_software_lateness_ns",
        "max_tx_to_capture_delta_ns",
        "max_post_veth_outgoing_release_lateness_ns",
        "network_receipt_sha256",
    }
    zero_failure_counts = {
        "rejected_attempts": 0,
        "late_schedule_outgoing_terminals": 0,
        "late_post_veth_outgoing_releases": 0,
        "late_incoming_advertisements": 0,
        "partial_outgoing_cells": 0,
        "suppressed_outgoing_cells": 0,
        "missed_directional_events": 0,
        "mismatched_outgoing_cells": 0,
        "catch_up_directional_events": 0,
        "unresolved_directional_events": 0,
        "retired_incoming_bytes": 0,
        "unresolved_incoming_bytes": 0,
        "runner_failed_kernel_tx_items": 0,
        "runner_unresolved_kernel_tx_items": 0,
        "evidence_unresolved_kernel_tx_items": 0,
        "qdisc_drops": 0,
        "qdisc_overlimits": 0,
        "qdisc_requeues": 0,
        "capture_drops": 0,
    }
    releases = aggregate.get("kernel_timed_outgoing_releases_after_tick_zero")
    outgoing = aggregate.get("outgoing_opportunities")
    incoming = aggregate.get("incoming_opportunities")
    opportunities_by_visit = aggregate.get("opportunities_per_direction_by_visit")
    drain_by_visit = aggregate.get("terminal_drain_opportunities_per_direction_by_visit")
    kernel = aggregate.get("kernel_tx")
    histogram = aggregate.get("kernel_timed_release_lateness_histogram_after_tick_zero")
    if (
        set(aggregate) != top_level_keys
        or type(releases) is not int
        or type(outgoing) is not int
        or type(incoming) is not int
        or not isinstance(kernel, Mapping)
        or set(kernel) != kernel_keys
        or not isinstance(histogram, Mapping)
        or set(histogram) != {"upper_bounds_nanoseconds", "counts"}
        or not isinstance(opportunities_by_visit, list)
        or len(opportunities_by_visit) != TIMING_STRESS_VISITS
        or any(type(value) is not int for value in opportunities_by_visit)
    ):
        raise ValueError("timing-stress aggregate counts or schema are malformed")
    histogram_counts = histogram.get("counts")
    incoming_bytes = incoming * TIMING_STRESS_PACKET_SIZE
    expected_release_outcomes = {
        "tick_zero_observed": TIMING_STRESS_VISITS,
        "kernel_timed_after_tick_zero": releases,
        "post_veth_matched": outgoing,
        "failed": 0,
    }
    if (
        aggregate.get("contract_schema_version") != TIMING_STRESS_SCHEMA_VERSION
        or aggregate.get("visits") != TIMING_STRESS_VISITS
        or aggregate.get("physical_attempts") != TIMING_STRESS_VISITS
        or aggregate.get("rejected_attempts") != 0
        or not TIMING_STRESS_MINIMUM_TOTAL_GUARDS <= releases <= TIMING_STRESS_MAXIMUM_TOTAL_GUARDS
        or any(
            not TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
            <= value
            <= TIMING_STRESS_MAX_EVENTS_PER_DIRECTION
            for value in opportunities_by_visit
        )
        or sum(opportunities_by_visit) != outgoing
        or not isinstance(drain_by_visit, list)
        or drain_by_visit
        != [
            value - TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION
            for value in opportunities_by_visit
        ]
        or aggregate.get("mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero")
        != TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        or aggregate.get("terminal_drain_kernel_timed_outgoing_releases_after_tick_zero")
        != releases - TIMING_STRESS_MINIMUM_TOTAL_GUARDS
        or aggregate.get("release_outcomes") != expected_release_outcomes
        or not TIMING_STRESS_MINIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        <= outgoing
        <= TIMING_STRESS_MAXIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        or outgoing != incoming
        or releases != outgoing - TIMING_STRESS_VISITS
        or aggregate.get("directional_events") != outgoing + incoming
        or aggregate.get("full_outgoing_cells") != outgoing
        or aggregate.get("terminal_drain_opportunities_per_direction")
        != outgoing - TIMING_STRESS_MINIMUM_TOTAL_OPPORTUNITIES_PER_DIRECTION
        or aggregate.get("terminal_drain_opportunities_per_direction") != sum(drain_by_visit)
        or aggregate.get("incoming_credit_bytes")
        != {
            "requested": incoming_bytes,
            "advertised": incoming_bytes,
            "consumed": incoming_bytes,
            "retired": 0,
            "unresolved": 0,
        }
        or type(aggregate.get("terminal_resolution_row_reorderings")) is not int
        or aggregate["terminal_resolution_row_reorderings"] < 0
        or aggregate.get("minimum_last_target_time_us")
        != (min(opportunities_by_visit) - 1) * TIMING_STRESS_INTERVAL_US
        or aggregate.get("maximum_last_target_time_us")
        != (max(opportunities_by_visit) - 1) * TIMING_STRESS_INTERVAL_US
        or type(aggregate.get("max_schedule_outgoing_terminal_lateness_us")) is not int
        or not 0
        <= aggregate["max_schedule_outgoing_terminal_lateness_us"]
        < TIMING_STRESS_WINDOW_US
        or type(aggregate.get("max_incoming_credit_advertisement_delay_us")) is not int
        or not 0
        <= aggregate["max_incoming_credit_advertisement_delay_us"]
        < TIMING_STRESS_WINDOW_US
        or aggregate.get("realization_backend") != "linux-etf-so-txtime-post-veth-v1"
        or aggregate.get("runner_wakeup_schema_version") != 11
        or aggregate.get("legacy_userspace_exact_release_projection")
        != {
            "schema_version": 10,
            "neutral_visits": TIMING_STRESS_VISITS,
            "nonneutral_visits": 0,
        }
        or kernel.get("runner_receipt_schema_version") != 2
        or kernel.get("evidence_schema_version") != 1
        or kernel.get("observer_topology_schema_version") != 1
        or kernel.get("job_count") != outgoing
        or kernel.get("etf_item_count") != outgoing
        or type(kernel.get("item_count")) is not int
        or kernel["item_count"] < outgoing
        or kernel.get("ordered_item_count") != kernel["item_count"] - outgoing
        or type(kernel.get("captured_credit_identity_count")) is not int
        or kernel["captured_credit_identity_count"] < 0
        or kernel.get("matched_item_count") != kernel["item_count"]
        or any(
            kernel.get(key) != 0
            for key in (
                "runner_failed_item_count",
                "runner_unresolved_item_count",
                "evidence_unresolved_item_count",
                "qdisc_drop_count",
                "qdisc_overlimit_count",
                "qdisc_requeue_count",
                "capture_drop_count",
            )
        )
        or any(
            type(kernel.get(key)) is not int
            or not 0 <= kernel[key] < TIMING_STRESS_WINDOW_US * 1_000
            for key in (
                "max_tx_software_lateness_ns",
                "max_tx_to_capture_delta_ns",
                "max_post_veth_outgoing_release_lateness_ns",
            )
        )
        or not isinstance(kernel.get("network_receipt_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", kernel["network_receipt_sha256"]) is None
        or histogram.get("upper_bounds_nanoseconds") != RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS
        or not isinstance(histogram_counts, list)
        or len(histogram_counts) != len(RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS) + 1
        or any(type(count) is not int or count < 0 for count in histogram_counts)
        or sum(histogram_counts) != releases
        or histogram_counts[-1] != 0
        or aggregate.get("zero_failure_counts") != zero_failure_counts
        or aggregate.get("observed_sensitivity") != _timing_stress_kernel_sensitivity(releases)
        or aggregate.get("passed") is not True
    ):
        raise ValueError("timing-stress aggregate zero-failure gate did not pass")


def _timing_stress_local_binding(root: Path, path: Path) -> dict[str, str]:
    path = path.resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("timing-stress local binding escapes its evidence root")
    return {"path": path.relative_to(root.resolve()).as_posix(), "sha256": sha256_file(path)}


def _validate_timing_stress_root_inventory(root: Path) -> None:
    """Close the stress receipt and its immutable input tree against stray files."""

    def exact_directory(
        directory: Path,
        *,
        files: set[str],
        directories: set[str] | None = None,
    ) -> None:
        directory_names = directories or set()
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"timing-stress evidence directory is invalid: {directory}")
        entries = {entry.name: entry for entry in directory.iterdir()}
        if set(entries) != files | directory_names:
            raise ValueError(f"timing-stress evidence inventory is not closed: {directory}")
        if any(
            entry.is_symlink()
            or (name in files and not entry.is_file())
            or (name in directory_names and not entry.is_dir())
            for name, entry in entries.items()
        ):
            raise ValueError(f"timing-stress evidence entry type is invalid: {directory}")

    exact_directory(
        root,
        files={"receipt.json", "experiment.json"},
        directories={"attempts", "inputs"},
    )
    inputs = root / "inputs"
    exact_directory(
        inputs,
        files={"study-environment.json"},
        directories={"application", "application-response-qualification", "chaff"},
    )
    exact_directory(
        inputs / "application",
        files={"complex.json", "runtime-complex.json"},
    )
    exact_directory(
        inputs / "application-response-qualification",
        files={"complex.json"},
    )
    exact_directory(inputs / "chaff", files={"qualified-manifest.json"})


def _timing_stress_sensitivity(
    guard_population: int = TIMING_STRESS_MINIMUM_TOTAL_GUARDS,
) -> dict[str, Any]:
    if type(guard_population) is not int or guard_population < TIMING_STRESS_MINIMUM_TOTAL_GUARDS:
        raise ValueError("timing-stress sensitivity population is below the mandatory prefix")
    return {
        "guard_population": guard_population,
        "iid_sensitivity_target_failures_per_guard": 1 / 20_000,
        "iid_detection_probability_at_target": 1 - (1 - 1 / 20_000) ** guard_population,
        "zero_failure_one_sided_95_percent_upper_rate": (1 - 0.05 ** (1 / guard_population)),
        "interpretation": (
            "descriptive-iid-sensitivity-only;temporally-correlated-guards-"
            "make-zero-observed-failures-the-actual-gate"
        ),
    }


def _timing_stress_kernel_sensitivity(
    release_population: int = TIMING_STRESS_MINIMUM_TOTAL_GUARDS,
) -> dict[str, Any]:
    """Describe v3 sensitivity in terms of observed post-tick-zero releases."""

    if (
        type(release_population) is not int
        or release_population < TIMING_STRESS_MINIMUM_TOTAL_GUARDS
    ):
        raise ValueError("timing-stress sensitivity population is below the mandatory prefix")
    return {
        "kernel_timed_outgoing_release_population_after_tick_zero": release_population,
        "iid_sensitivity_target_failures_per_release": 1 / 20_000,
        "iid_detection_probability_at_target": 1 - (1 - 1 / 20_000) ** release_population,
        "zero_failure_one_sided_95_percent_upper_rate": (1 - 0.05 ** (1 / release_population)),
        "interpretation": (
            "descriptive-iid-sensitivity-only;temporally-correlated-kernel-releases-"
            "make-zero-observed-failures-the-actual-gate"
        ),
    }


def execute_buflo_timing_stress(
    destination: Path,
    *,
    network_receipt: Mapping[str, Any],
    cohort_version: int,
) -> Path:
    """Run/resume twelve captured, one-launch, two-origin BuFLO stress visits."""

    from types import SimpleNamespace

    from . import capture_session
    from .chaff_qualification import load_response_qualified_chaff
    from .manifest import canonical_bytes, runtime_manifest

    version = _cohort_version(cohort_version)
    root = destination.resolve() / "buflo-timing-stress"
    receipt_path = root / "receipt.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        validate_buflo_timing_stress_receipt(receipt_path)
        return receipt_path
    for directory in (
        root,
        root / "inputs/application",
        root / "inputs/application-response-qualification",
        root / "inputs/chaff",
        root / "attempts",
    ):
        if directory.is_symlink():
            raise ValueError(f"timing-stress path cannot be a symlink: {directory}")
        directory.mkdir(parents=True, exist_ok=True)

    source = source_metadata()
    _validate_clean_source(source, label="timing-stress source")
    _validate_shared_router_network_receipt(
        network_receipt,
        client_qdisc="none",
        server_qdisc="none",
        cohort_version=version,
    )
    if network_receipt.get("image_digest") != source["image_digest"]:
        raise ValueError("timing-stress network and current source images differ")
    environment_binding, environment = _timing_stress_environment_input(root, source)
    if environment["build_execution"].get("cohort_version") != version:
        raise ValueError("timing-stress build execution belongs to another cohort")
    parameter_inputs = _timing_stress_parameter_inputs()
    defense = _timing_stress_defense()

    application_root = root / "inputs/application"
    _create_regression_multi_origin_workload(application_root)
    application_path = application_root / "complex.json"
    application = load_json(application_path)
    runtime_path = application_root / "runtime-complex.json"
    _create_or_verify_bytes(
        runtime_path,
        canonical_bytes(runtime_manifest(application)),
        "timing-stress runtime workload",
    )
    qualification_root = root / "inputs/application-response-qualification"
    sidecar_path = qualification_root / "complex.json"
    if not sidecar_path.exists() and not sidecar_path.is_symlink():
        _qualify_local_workloads_named(("complex",), application_root, qualification_root)
    qualified = load_response_qualified_chaff(
        sidecar_path,
        workload_id="complex",
        base_manifest_path=application_path,
        expected_sidecar_schema_version=2,
        require_current_implementation=True,
    )
    chaff_path = root / "inputs/chaff/qualified-manifest.json"
    _create_or_verify_bytes(
        chaff_path,
        canonical_bytes(qualified.manifest),
        "timing-stress qualified chaff manifest",
    )
    checkpoint_binding = _timing_stress_checkpoint_binding(
        source,
        cohort_version=version,
        network_receipt=network_receipt,
        environment_binding=environment_binding,
        parameter_inputs=parameter_inputs,
        application_path=application_path,
        runtime_path=runtime_path,
        response_qualification_path=sidecar_path,
        response_qualification_manifest_sha256=qualified.manifest_sha256,
        chaff_path=chaff_path,
    )

    state_path = root / "experiment.json"
    if state_path.exists() or state_path.is_symlink():
        if state_path.is_symlink() or not state_path.is_file():
            raise ValueError("timing-stress checkpoint is not a regular file")
        state = load_json(state_path)
    else:
        state = {
            "schema_version": TIMING_STRESS_SCHEMA_VERSION,
            "artifact_type": TIMING_STRESS_CHECKPOINT_TYPE,
            "campaign_binding": checkpoint_binding,
            "launched_visits": {},
            "accepted_visits": {},
        }
    _validate_timing_stress_checkpoint(
        state,
        require_complete=False,
        expected_binding=checkpoint_binding,
    )
    limits = capture_session.Limits(
        timeout_seconds=120,
        max_response_bytes=1_048_576,
        capture_seconds=180,
        capture_megabytes=64,
        max_attempts=1,
        per_origin_cooldown_seconds=0,
        settle_seconds=1,
    )
    context = SimpleNamespace(
        qcsd_profile="research-1200",
        request_policy="as-defined",
        limits=limits,
        udp_payload_ceiling=1_200,
    )
    samples: list[dict[str, Any]] = []
    for visit in range(TIMING_STRESS_VISITS):
        visit_name = f"visit-{visit:03d}"
        visit_root = root / "attempts" / visit_name
        if visit_root.is_symlink():
            raise ValueError("timing-stress visit root cannot be a symlink")
        visit_root.mkdir(parents=True, exist_ok=True)
        attempt = visit_root / "attempt-01"
        relative = attempt.relative_to(root).as_posix()
        recorded = state["accepted_visits"].get(visit_name)
        recorded_launch = state["launched_visits"].get(visit_name)
        if (recorded is not None and recorded != relative) or (
            recorded_launch is not None and recorded_launch != relative
        ):
            raise ValueError("timing-stress checkpoint changed its physical launch")
        newly_reserved = False
        if recorded_launch is None:
            if attempt.exists() or attempt.is_symlink():
                raise ValueError("timing-stress unrecorded first-launch evidence is terminal")
            newly_reserved = _timing_stress_reserve_launch(
                state_path,
                state,
                visit_name=visit_name,
                relative_attempt=relative,
            )
            recorded_launch = relative
        seed = _stable_seed(TIMING_STRESS_SEED_NAMESPACE, visit_name)
        try:
            _timing_stress_collect_or_resume(
                attempt,
                lambda attempt=attempt, seed=seed: _with_kernel_tx_network_receipt(
                    network_receipt,
                    lambda: capture_session._collect_attempt(
                        attempt,
                        runtime_path,
                        chaff_path,
                        "complex",
                        defense,
                        seed,
                        context,
                        application_workload_source=application_path,
                    ),
                ),
                recorded_attempt=recorded_launch,
                newly_reserved=newly_reserved,
            )
        except (
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as error:
            if not attempt.is_symlink() and (not attempt.exists() or attempt.is_dir()):
                _timing_stress_persist_rejection(
                    attempt,
                    error,
                    stage="timing-stress-collection",
                )
            atomic_json(state_path, state)
            raise ValueError(
                f"timing-stress {visit_name} first launch failed; no retry is allowed"
            ) from error
        try:
            evidence = _timing_stress_attempt_evidence(
                attempt,
                root=root,
                application_path=application_path,
                runtime_path=runtime_path,
                chaff_path=chaff_path,
                defense=defense,
                visit=visit,
                network_receipt=network_receipt,
            )
        except (OSError, TypeError, ValueError) as error:
            _timing_stress_persist_rejection(
                attempt,
                error,
                stage="timing-stress-eligibility",
            )
            atomic_json(state_path, state)
            raise ValueError(
                f"timing-stress {visit_name} is ineligible; no retry is allowed"
            ) from error
        state["accepted_visits"][visit_name] = relative
        atomic_json(state_path, state)
        samples.append(evidence)

    accepted_visits = _validate_timing_stress_checkpoint(
        state,
        require_complete=True,
        expected_binding=checkpoint_binding,
    )
    ledgers = _timing_stress_attempt_ledgers(
        root,
        application_path=application_path,
        runtime_path=runtime_path,
        chaff_path=chaff_path,
        defense=defense,
        accepted_visits=accepted_visits,
        samples=samples,
        network_receipt=network_receipt,
    )
    aggregate = _timing_stress_aggregate(samples)
    _validate_timing_stress_aggregate(aggregate)
    value = {
        "schema_version": TIMING_STRESS_SCHEMA_VERSION,
        "artifact_type": TIMING_STRESS_ARTIFACT_TYPE,
        "status": "passed",
        "evidence_class": "timing-stress-nonformal-excluded",
        "source": dict(source),
        "cohort_version": version,
        "study_plan": _file_binding(STUDY_PLAN),
        "network": deepcopy(dict(network_receipt)),
        "environment": environment_binding,
        "inputs": {
            "parameters": parameter_inputs,
            "application_workload": _timing_stress_local_binding(root, application_path),
            "runtime_workload": _timing_stress_local_binding(root, runtime_path),
            "response_qualification": {
                **_timing_stress_local_binding(root, sidecar_path),
                "derived_manifest_sha256": qualified.manifest_sha256,
            },
            "qualified_chaff_manifest": _timing_stress_local_binding(root, chaff_path),
        },
        "experiment": _timing_stress_local_binding(root, state_path),
        "resume_authority": {
            "path": "experiment.json",
            "semantics": "authoritative-single-physical-launch-per-visit",
            "max_attempts_per_visit": 1,
            "launch_reserved_atomically_before_collection": True,
            "completed_first_launch_revalidated_without_relaunch": True,
            "rejected_or_incomplete_first_launch_terminal": True,
            "checkpoint_binds_cohort_source_and_inputs": True,
        },
        "opportunity_contract": deepcopy(load_study_plan()["timing_stress"]),
        "sensitivity": _timing_stress_kernel_sensitivity(),
        "attempt_ledgers": ledgers,
        "samples": samples,
        "aggregate": aggregate,
        "regression_matrix_samples": 18,
        "excluded_from_regression_matrix": True,
        "passed": True,
    }
    if environment["image_id"] != source["image_digest"]:
        raise ValueError("timing-stress environment differs from its source image")
    _create_only_json(receipt_path, value)
    validate_buflo_timing_stress_receipt(receipt_path)
    return receipt_path


def validate_buflo_timing_stress_receipt(
    receipt_path: Path,
    *,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Deep-reconstruct the excluded 60,000-release prefix and audited drain suffix."""

    from .chaff_qualification import load_response_qualified_chaff
    from .manifest import canonical_bytes, runtime_manifest, validate_research_preparation

    receipt_path = receipt_path.absolute()
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("timing-stress receipt is not a regular file")
    receipt_path = receipt_path.resolve()
    root = receipt_path.parent
    _validate_timing_stress_root_inventory(root)
    value = load_json(receipt_path)
    required = {
        "schema_version",
        "artifact_type",
        "status",
        "evidence_class",
        "source",
        "cohort_version",
        "study_plan",
        "network",
        "environment",
        "inputs",
        "experiment",
        "resume_authority",
        "opportunity_contract",
        "sensitivity",
        "attempt_ledgers",
        "samples",
        "aggregate",
        "regression_matrix_samples",
        "excluded_from_regression_matrix",
        "passed",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != TIMING_STRESS_SCHEMA_VERSION
        or value.get("artifact_type") != TIMING_STRESS_ARTIFACT_TYPE
        or value.get("status") != "passed"
        or value.get("evidence_class") != "timing-stress-nonformal-excluded"
        or value.get("regression_matrix_samples") != 18
        or value.get("excluded_from_regression_matrix") is not True
        or value.get("passed") is not True
    ):
        raise ValueError("timing-stress receipt contract is invalid")
    version = _cohort_version(value.get("cohort_version"))
    _validate_clean_source(value["source"], label="timing-stress receipt")
    expected_source = _expected_clean_collection_source(
        _expected_collection_source,
        label="timing-stress collection image",
    )
    if dict(value["source"]) != expected_source:
        raise ValueError("timing-stress receipt does not bind the current source")
    if value["study_plan"] != _file_binding(STUDY_PLAN):
        raise ValueError("timing-stress study-plan binding changed")
    if value["opportunity_contract"] != load_study_plan()["timing_stress"]:
        raise ValueError("timing-stress opportunity contract changed")
    if value["sensitivity"] != _timing_stress_kernel_sensitivity():
        raise ValueError("timing-stress statistical sensitivity disclosure changed")
    if value["resume_authority"] != {
        "path": "experiment.json",
        "semantics": "authoritative-single-physical-launch-per-visit",
        "max_attempts_per_visit": 1,
        "launch_reserved_atomically_before_collection": True,
        "completed_first_launch_revalidated_without_relaunch": True,
        "rejected_or_incomplete_first_launch_terminal": True,
        "checkpoint_binds_cohort_source_and_inputs": True,
    }:
        raise ValueError("timing-stress experiment.json resume authority changed")

    network = value["network"]
    _validate_shared_router_network_receipt(
        network,
        client_qdisc="none",
        server_qdisc="none",
        cohort_version=version,
    )
    if network.get("image_digest") != value["source"]["image_digest"]:
        raise ValueError("timing-stress network image differs from its source")
    environment_path = _regression_multi_origin_bound_path(
        root, value["environment"], label="timing-stress environment"
    )
    environment = validate_study_environment_receipt(
        load_json(environment_path),
        expected_image_digest=value["source"]["image_digest"],
    )
    if environment["image_id"] != value["source"]["image_digest"]:
        raise ValueError("timing-stress environment does not use the current image")
    if environment["build_execution"].get("cohort_version") != version:
        raise ValueError("timing-stress build execution belongs to another cohort")

    inputs = value["inputs"]
    if not isinstance(inputs, Mapping) or set(inputs) != {
        "parameters",
        "application_workload",
        "runtime_workload",
        "response_qualification",
        "qualified_chaff_manifest",
    }:
        raise ValueError("timing-stress input inventory is invalid")
    expected_parameters = _timing_stress_parameter_inputs()
    if inputs["parameters"] != expected_parameters:
        raise ValueError("timing-stress parameter derivation changed")
    application_path = _regression_multi_origin_bound_path(
        root, inputs["application_workload"], label="timing-stress application"
    )
    runtime_path = _regression_multi_origin_bound_path(
        root, inputs["runtime_workload"], label="timing-stress runtime workload"
    )
    application = load_json(application_path)
    validate_research_preparation(application, workload_id="complex")
    if load_json(runtime_path) != runtime_manifest(application):
        raise ValueError("timing-stress runtime workload is not exactly derived")
    sidecar_path = _regression_multi_origin_bound_path(
        root,
        inputs["response_qualification"],
        fields={"path", "sha256", "derived_manifest_sha256"},
        label="timing-stress response qualification",
    )
    qualified = load_response_qualified_chaff(
        sidecar_path,
        workload_id="complex",
        base_manifest_path=application_path,
        expected_sidecar_schema_version=2,
        require_current_implementation=True,
    )
    if inputs["response_qualification"]["derived_manifest_sha256"] != qualified.manifest_sha256:
        raise ValueError("timing-stress response qualification derivation changed")
    chaff_path = _regression_multi_origin_bound_path(
        root,
        inputs["qualified_chaff_manifest"],
        label="timing-stress qualified chaff manifest",
    )
    if chaff_path.read_bytes() != canonical_bytes(qualified.manifest):
        raise ValueError("timing-stress chaff manifest is not exactly derived")

    checkpoint_path = _regression_multi_origin_bound_path(
        root, value["experiment"], label="timing-stress experiment checkpoint"
    )
    if checkpoint_path != root / "experiment.json":
        raise ValueError("timing-stress experiment.json is not the authoritative checkpoint")
    accepted_visits = _validate_timing_stress_checkpoint(
        load_json(checkpoint_path),
        require_complete=True,
        expected_binding=_timing_stress_checkpoint_binding(
            value["source"],
            cohort_version=version,
            network_receipt=network,
            environment_binding=value["environment"],
            parameter_inputs=expected_parameters,
            application_path=application_path,
            runtime_path=runtime_path,
            response_qualification_path=sidecar_path,
            response_qualification_manifest_sha256=qualified.manifest_sha256,
            chaff_path=chaff_path,
        ),
    )
    defense = _timing_stress_defense()
    samples = value["samples"]
    if not isinstance(samples, list) or len(samples) != TIMING_STRESS_VISITS:
        raise ValueError("timing-stress sample inventory is incomplete")
    verified_samples: list[dict[str, Any]] = []
    for visit, record in enumerate(samples):
        if not isinstance(record, Mapping) or record.get("visit") != visit:
            raise ValueError("timing-stress sample order is invalid")
        relative = record.get("attempt")
        expected_relative = f"attempts/visit-{visit:03d}/attempt-01"
        if relative != expected_relative:
            raise ValueError("timing-stress sample does not bind its sole physical launch")
        attempt = root / expected_relative
        expected = _timing_stress_attempt_evidence(
            attempt,
            root=root,
            application_path=application_path,
            runtime_path=runtime_path,
            chaff_path=chaff_path,
            defense=defense,
            visit=visit,
            network_receipt=network,
        )
        if dict(record) != expected:
            raise ValueError("timing-stress sample evidence changed")
        verified_samples.append(expected)
    expected_ledgers = _timing_stress_attempt_ledgers(
        root,
        application_path=application_path,
        runtime_path=runtime_path,
        chaff_path=chaff_path,
        defense=defense,
        accepted_visits=accepted_visits,
        samples=verified_samples,
        network_receipt=network,
    )
    if value["attempt_ledgers"] != expected_ledgers:
        raise ValueError("timing-stress attempt ledger changed")
    aggregate = _timing_stress_aggregate(verified_samples)
    if value["aggregate"] != aggregate:
        raise ValueError("timing-stress aggregate evidence changed")
    _validate_timing_stress_aggregate(aggregate)
    return {
        "schema_version": TIMING_STRESS_SCHEMA_VERSION,
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "source": dict(value["source"]),
        "cohort_version": version,
        "environment": environment,
        "network": deepcopy(dict(network)),
        "visits": TIMING_STRESS_VISITS,
        "physical_attempts": TIMING_STRESS_VISITS,
        "rejected_attempts": 0,
        "kernel_timed_outgoing_releases_after_tick_zero": aggregate[
            "kernel_timed_outgoing_releases_after_tick_zero"
        ],
        "outgoing_opportunities": aggregate["outgoing_opportunities"],
        "incoming_opportunities": aggregate["incoming_opportunities"],
        "directional_events": aggregate["directional_events"],
        "full_outgoing_cells": aggregate["full_outgoing_cells"],
        "incoming_credit_bytes": deepcopy(aggregate["incoming_credit_bytes"]),
        "terminal_drain_opportunities_per_direction": aggregate[
            "terminal_drain_opportunities_per_direction"
        ],
        "observed_sensitivity": deepcopy(aggregate["observed_sensitivity"]),
        "excluded_from_regression_matrix": True,
        "passed": True,
    }


def _validate_timing_stress_binding(
    value: object,
    *,
    expected_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"path", "sha256"}
        or not isinstance(value.get("path"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256"))) is None
    ):
        raise ValueError("regression timing-stress binding is malformed")
    path = Path(value["path"])
    if (
        path.name != "receipt.json"
        or path.parent.name != "buflo-timing-stress"
        or path.is_symlink()
        or not path.is_file()
        or sha256_file(path) != value["sha256"]
    ):
        raise ValueError("regression timing-stress receipt changed")
    return validate_buflo_timing_stress_receipt(
        path,
        _expected_collection_source=expected_source,
    )


def _validate_current_regression_timing_stress(
    regression_receipts: Sequence[Mapping[str, Any]],
    *,
    destination: Path,
    lineage: Mapping[str, Any],
    expected_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require one exact sibling stress gate across all current regression shards."""

    if (
        len(regression_receipts) != len(LOCAL_STAGE_RESULT_NAMES["regression"])
        or any(
            receipt.get("schema_version") != TIMING_STRESS_BOUND_REGRESSION_RECEIPT_SCHEMA_VERSION
            for receipt in regression_receipts
        )
        or len({_canonical_digest(receipt) for receipt in regression_receipts}) != 1
    ):
        raise ValueError("current regression shards lack one exact mandatory timing-stress binding")
    receipt = regression_receipts[0]
    timing_binding = receipt["timing_stress"]
    timing_stress = _validate_timing_stress_binding(
        timing_binding,
        expected_source=expected_source,
    )
    expected_path = destination.resolve() / "buflo-timing-stress/receipt.json"
    if Path(timing_binding["path"]).resolve() != expected_path:
        raise ValueError("regression timing-stress receipt is not its exact sibling gate")
    stress_value = load_json(expected_path)
    network = stress_value.get("network") if isinstance(stress_value, Mapping) else None
    if (
        timing_stress["source"] != lineage
        or timing_stress["network"] != network
        or receipt["network"] != network
        or timing_stress["cohort_version"] != receipt["cohort_version"]
        or timing_stress["source"].get("image_digest") != receipt["network"].get("image_digest")
    ):
        raise ValueError(
            "regression timing-stress source, image, network, or cohort binding differs"
        )
    return timing_stress


def _local_controlled_campaign_document(
    campaign_path: Path, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    def relative(path: Path) -> str:
        return os.path.relpath(path, campaign_path.parent)

    return {
        "schema": 1,
        "name": f"buflo-study-v1-controlled-{receipt['netem_rank']:02d}-1200",
        "purpose": "smoke",
        "seed": 2_027_082_700 + int(receipt["netem_rank"]),
        "profile": "research-1200",
        "defense_order": {
            "scheme": "cyclic-latin-square",
            "block": receipt["netem_rank"],
        },
        "study_controlled": dict(receipt),
        "workloads": {"local-small": 5, "local-large": 5},
        "request_policies": ["as-defined"],
        "defenses": [
            "undefended",
            {
                "name": "buflo",
                "kind": "buflo",
                "parameters": relative(PARAMETER_FILES["buflo"][1]),
            },
            {
                "name": "cs-buflo-cpsp",
                "kind": "cs_buflo",
                "parameters": relative(PARAMETER_FILES["cs-buflo-cpsp"][1]),
            },
            {
                "name": "cs-buflo-ctsp",
                "kind": "cs_buflo",
                "parameters": relative(PARAMETER_FILES["cs-buflo-ctsp"][1]),
            },
        ],
        "limits": {
            "timeout_seconds": 120,
            "max_response_bytes": 1_048_576,
            "capture_seconds": 180,
            "capture_megabytes": 64,
            "max_attempts": 3,
            "per_origin_cooldown_seconds": 0,
            "settle_seconds": 1,
        },
    }


def _local_regression_campaign_documents(
    campaign_root: Path,
    receipt: Mapping[str, Any],
    walkie_talkie: Path,
) -> tuple[tuple[str, dict[str, Any]], ...]:
    def relative(path: Path) -> str:
        return os.path.relpath(path, campaign_root)

    common = {
        "schema": 1,
        "purpose": "smoke",
        "seed": 2_027_082_710,
        "defense_order": {"scheme": "cyclic-latin-square", "block": 0},
        "study_controlled": dict(receipt),
        "workloads": {"simple": 1, "complex": 1},
        "request_policies": ["as-defined"],
        "limits": {
            "timeout_seconds": 120,
            "max_response_bytes": 1_048_576,
            "capture_seconds": 180,
            "capture_megabytes": 64,
            "max_attempts": 3,
            "per_origin_cooldown_seconds": 0,
            "settle_seconds": 1,
        },
    }
    old = {
        **common,
        "name": "buflo-study-v1-regression-established-seven-1200",
        "profile": "live",
        "defenses": [
            "undefended",
            {
                "name": "static",
                "kind": "static",
                "schedule": relative(LAB_ROOT / "config/defense-params/static-control-1200.csv"),
                "mode": "chaff-only",
            },
            "front",
            "tamaraw",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": relative(
                    LAB_ROOT / "config/defense-params/traffic-morphing-live.json"
                ),
            },
            {
                "name": "wtf-pad",
                "kind": "wtf_pad",
                "parameters": relative(LAB_ROOT / "config/defense-params/wtfpad-live.json"),
            },
            {
                "name": "walkie-talkie",
                "kind": "walkie_talkie",
                "parameters": relative(walkie_talkie),
            },
        ],
    }
    buflo = {
        **common,
        "name": "buflo-study-v1-regression-buflo-1200",
        "seed": 2_027_082_711,
        "profile": "research-1200",
        "defenses": [
            {
                "name": "buflo",
                "kind": "buflo",
                "parameters": relative(PARAMETER_FILES["buflo"][1]),
            }
        ],
    }
    cs_buflo = {
        **common,
        "name": "buflo-study-v1-regression-cs-buflo-1200",
        "seed": 2_027_082_712,
        "profile": "research-1200",
        "defenses": [
            {
                "name": "cs-buflo",
                "kind": "cs_buflo",
                "parameters": relative(PARAMETER_FILES["cs-buflo"][1]),
            }
        ],
    }
    return (
        ("buflo-study-v1-regression-established-seven.yml", old),
        ("buflo-study-v1-regression-buflo.yml", buflo),
        ("buflo-study-v1-regression-cs-buflo.yml", cs_buflo),
    )


def _run_local_campaign_set(
    campaigns: Sequence[Path],
    destination: Path,
    *,
    state_name: str,
    network_receipt: Mapping[str, Any],
) -> tuple[Path, ...]:
    from .orchestrator import CampaignIncomplete, resume_campaign, run_campaign
    from .verification import verify_result

    state_path = destination / state_name
    if state_path.exists():
        if state_path.is_symlink() or not state_path.is_file():
            raise ValueError("local campaign-set checkpoint is not a regular file")
        state = load_json(state_path)
    else:
        state = {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-local-campaign-set-checkpoint",
            "campaigns": {},
        }
    if (
        not isinstance(state, dict)
        or set(state) != {"schema_version", "artifact_type", "campaigns"}
        or state["schema_version"] != 1
        or state["artifact_type"] != "qcsd-buflo-local-campaign-set-checkpoint"
        or not isinstance(state["campaigns"], dict)
    ):
        raise ValueError("local campaign-set checkpoint is invalid")
    results: list[Path] = []
    for campaign in campaigns:
        document = yaml.safe_load(campaign.read_text(encoding="utf-8"))
        name = document["name"]
        recorded = state["campaigns"].get(name)
        if recorded is not None:
            if not isinstance(recorded, str):
                raise ValueError("local campaign checkpoint result path is invalid")
            result = Path(recorded).resolve()
            if not result.is_relative_to(destination):
                raise ValueError("local campaign checkpoint escapes its destination")
            try:
                verified = verify_result(result)
            except (OSError, ValueError):
                result = _with_kernel_tx_network_receipt(network_receipt, resume_campaign, result)
            else:
                if verified.experiment["status"] != "complete":
                    result = _with_kernel_tx_network_receipt(
                        network_receipt, resume_campaign, result
                    )
        else:
            candidates = sorted(
                (destination / "results" / name).glob("*"), key=lambda path: path.name
            )
            if len(candidates) > 1:
                raise ValueError(f"local campaign {name} has multiple unbound results")
            if candidates:
                result = _with_kernel_tx_network_receipt(
                    network_receipt, resume_campaign, candidates[0]
                )
            else:
                try:
                    result = _with_kernel_tx_network_receipt(
                        network_receipt,
                        run_campaign,
                        campaign,
                        destination / "results",
                    )
                except CampaignIncomplete as error:
                    result = error.root
                    state["campaigns"][name] = str(result)
                    atomic_json(state_path, state)
                    raise
            state["campaigns"][name] = str(result)
            atomic_json(state_path, state)
        verified = verify_result(result)
        if verified.experiment["status"] != "complete":
            raise ValueError(f"local campaign {name} remains incomplete")
        results.append(result)
    return tuple(results)


def _create_or_verify_bytes(path: Path, value: bytes, label: str) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != value:
            raise ValueError(f"{label} changed after prospective creation: {path}")
        return
    try:
        with path.open("xb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != value:
            raise ValueError(f"{label} raced during prospective creation: {path}") from None


def _load_local_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-controlled-results-checkpoint",
            "profiles": {},
        }
    if path.is_symlink() or not path.is_file():
        raise ValueError("local controlled checkpoint is not a regular file")
    value = load_json(path)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "artifact_type", "profiles"}
        or value["schema_version"] != 1
        or value["artifact_type"] != "qcsd-buflo-controlled-results-checkpoint"
        or not isinstance(value["profiles"], dict)
        or any(
            profile
            not in {item["id"] for item in load_study_plan()["controlled"]["netem_profiles"]}
            or not isinstance(result, str)
            for profile, result in value["profiles"].items()
        )
    ):
        raise ValueError("local controlled checkpoint is invalid")
    return value


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _campaign_document(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"BuFLO campaign is not a regular file: {path}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError(f"BuFLO campaign is invalid: {path}") from error
    if not isinstance(value, dict):
        raise TypeError(f"BuFLO campaign must be an object: {path}")
    return value


def _validate_campaign_document(
    value: Mapping[str, Any],
    stage: str,
    index: int,
    seed: int,
    plan: Mapping[str, Any],
    *,
    qualification_set: str | None = None,
) -> None:
    expected_qualification_set = qualification_set or str(plan["qualification_set"])
    expected_keys = {
        "schema",
        "name",
        "purpose",
        "seed",
        "profile",
        "chaff_qualification_set",
        "workloads",
        "request_policies",
        "defenses",
        "limits",
    } | ({"defense_order"} if stage == "formal" else set())
    if set(value) != expected_keys:
        raise ValueError(f"BuFLO {stage} campaign fields are invalid")
    expected_name = (
        f"buflo-study-v1-formal-{index + 1:02d}-1200"
        if stage == "formal"
        else f"buflo-study-v1-public-{stage}-1200"
    )
    expected_purpose = "smoke" if stage == "smoke" else "evaluation"
    visits = plan["public_stages"][stage]["visits_per_workload"]
    workload_order = WORKLOADS[index % len(WORKLOADS) :] + WORKLOADS[: index % len(WORKLOADS)]
    if stage != "formal":
        workload_order = WORKLOADS
    if (
        value["schema"] != 1
        or value["name"] != expected_name
        or value["purpose"] != expected_purpose
        or value["seed"] != seed
        or value["profile"] != "research-1200"
        or value["chaff_qualification_set"] != expected_qualification_set
        or tuple(value["workloads"]) != workload_order
        or set(value["workloads"].values()) != {visits}
        or value["request_policies"] != ["as-defined"]
        or value["limits"] != COMMON_LIMITS
        or tuple(_defense_name(item) for item in value["defenses"]) != STAGE_TREATMENTS[stage]
    ):
        raise ValueError(f"BuFLO {stage} campaign contract drifted")
    if stage == "formal" and value.get("defense_order") != {
        "scheme": "cyclic-latin-square",
        "block": index,
    }:
        raise ValueError("formal campaign must use its exact cyclic Latin-square phase")
    for item in value["defenses"]:
        name = _defense_name(item)
        if name == "undefended":
            if item != "undefended":
                raise ValueError("undefended treatment must use its canonical shorthand")
            continue
        if not isinstance(item, dict) or set(item) != {"name", "kind", "parameters"}:
            raise ValueError(f"BuFLO treatment {name} is malformed")
        expected_kind, expected_path = PARAMETER_FILES[name]
        expected_relative = f"../defense-params/{expected_path.name}"
        if item["kind"] != expected_kind or item["parameters"] != expected_relative:
            raise ValueError(f"BuFLO treatment {name} parameter binding drifted")


def _defense_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("name"), str):
        return value["name"]
    raise ValueError("BuFLO campaign defense is malformed")


def _stable_seed(*parts: object) -> int:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return int(digest.hexdigest()[:16], 16)


def _accumulate_positions(
    positions: dict[tuple[str, str], list[int]], value: Mapping[str, Any]
) -> None:
    treatments = tuple(_defense_name(item) for item in value["defenses"])
    for workload, visits in value["workloads"].items():
        for treatment in treatments:
            positions.setdefault((workload, treatment), [0] * len(treatments))
        workload_rank = sorted(value["workloads"]).index(workload)
        for visit in range(visits):
            order = list(treatments)
            defense_order = value.get("defense_order")
            if isinstance(defense_order, Mapping):
                phase = (defense_order["block"] + workload_rank + visit) % len(order)
                order = order[phase:] + order[:phase]
            else:
                random.Random(
                    _stable_seed("defense-order", value["seed"], workload, "as-defined", visit)
                ).shuffle(order)
            for index, treatment in enumerate(order):
                positions[(workload, treatment)][index] += 1


def validate_references(
    external_sources: Mapping[str, Path] | None = None,
) -> tuple[dict[str, Any], ...]:
    from .buflo_reference import (
        BUFLO_PROFILES,
        CSBUFLO_WPES14_PARAMETERS,
        BufloSourcePacket,
        CsBufloEmptyRatePolicy,
        CsBufloPadding,
        DeterministicCsBufloJitter,
        audit_csbuflo_archive,
        csbuflo_channel_idle,
        csbuflo_crossed_threshold,
        csbuflo_done_transmitting,
        csbuflo_estimate_rho_us,
        csbuflo_padding_target_bytes,
        transform_buflo,
        validate_reference_receipt,
    )

    supplied = {source_id: Path(path) for source_id, path in (external_sources or {}).items()}
    records = []
    for path in REFERENCE_FILES:
        prefix = "dyer-" if path.name.startswith("buflo-") else "csbuflo-"
        selected = {
            source_id: source_path
            for source_id, source_path in supplied.items()
            if source_id.startswith(prefix)
        }
        receipt = validate_reference_receipt(path, external_sources=selected)
        records.append(
            {
                "reference_id": receipt.reference_id,
                "path": str(receipt.reference_path),
                "sha256": receipt.reference_sha256,
                "receipt_path": str(receipt.receipt_path),
                "receipt_sha256": receipt.receipt_sha256,
                "verified_external_sources": list(receipt.verified_external_sources),
            }
        )
    if len(BUFLO_PROFILES) != 8:
        raise ValueError("BuFLO oracle does not expose all eight paper profiles")
    source = (
        BufloSourcePacket(0, "outgoing", 152),
        BufloSourcePacket(35, "incoming", 252),
        BufloSourcePacket(90, "outgoing", 1_052),
    )
    golden_counts = {}
    for profile in BUFLO_PROFILES:
        first = transform_buflo(source, profile)
        second = transform_buflo(source, profile)
        if first != second or not first:
            raise ValueError(f"BuFLO oracle is not deterministic for {profile.key}")
        ticks: dict[int, set[str]] = {}
        for emission in first:
            if emission.length_bytes != profile.packet_size_bytes:
                raise ValueError(f"BuFLO oracle violated fixed size for {profile.key}")
            ticks.setdefault(emission.monotonic_ms, set()).add(emission.direction)
        if any(directions != {"incoming", "outgoing"} for directions in ticks.values()):
            raise ValueError(f"BuFLO oracle violated bidirectional ticks for {profile.key}")
        ordered_ticks = sorted(ticks)
        if (
            ordered_ticks[0] != 0
            or any(
                current - previous != profile.rho_ms
                for previous, current in pairwise(ordered_ticks)
            )
            or ordered_ticks[-1] < profile.tau_ms
        ):
            raise ValueError(f"BuFLO oracle violated timing/minimum duration for {profile.key}")
        golden_counts[profile.key] = len(first)

    parameters = CSBUFLO_WPES14_PARAMETERS
    if (
        parameters.initial_rho_us,
        parameters.lower_rho_us,
        parameters.upper_rho_us,
        parameters.first_adaptation_boundary_bytes,
        parameters.write_size_bytes,
        parameters.nominal_wire_packet_bytes,
        parameters.quiet_time_us,
        parameters.jitter_denominator,
        parameters.jitter_max_numerator,
    ) != (8_192, 4_096, 32_768, 16_384, 548, 600, 2_000_000, 100, 200):
        raise ValueError("CS-BuFLO pinned-source defaults drifted")
    if (
        csbuflo_estimate_rho_us(
            (),
            8_192,
            empty_policy=CsBufloEmptyRatePolicy.PAPER_RETAIN_CURRENT,
        )
        != 8_192
        or csbuflo_estimate_rho_us(
            (),
            8_192,
            empty_policy=CsBufloEmptyRatePolicy.ARTIFACT_UPPER_BOUND,
        )
        != 32_768
    ):
        raise ValueError("CS-BuFLO paper/artifact empty-window variants drifted")
    jitter_a = DeterministicCsBufloJitter(7).delays_us(8_192, 16)
    jitter_b = DeterministicCsBufloJitter(7).delays_us(8_192, 16)
    if jitter_a != jitter_b or any(not 0 <= value <= 16_384 for value in jitter_a):
        raise ValueError("CS-BuFLO seeded discrete jitter golden failed")
    if (
        csbuflo_padding_target_bytes(600, 1_500, CsBufloPadding.TOTAL) != 4_096
        or csbuflo_padding_target_bytes(600, 1_500, CsBufloPadding.PAYLOAD) != 3_072
        or not csbuflo_crossed_threshold(1_024, packet_size_bytes=548)
        or csbuflo_channel_idle(
            on_load_event=False,
            last_site_response_us=0,
            now_us=2_000_000,
        )
        or not csbuflo_channel_idle(
            on_load_event=False,
            last_site_response_us=0,
            now_us=2_000_001,
        )
    ):
        raise ValueError("CS-BuFLO padding/termination oracle goldens failed")
    # Exercise the full termination helper as part of the reference gate.
    if not csbuflo_done_transmitting(
        output_buffer_bytes=0,
        on_load_event=True,
        last_site_response_us=None,
        now_us=0,
        padding_done=True,
        total_sent_bytes=0,
    ):
        raise ValueError("CS-BuFLO done-transmitting oracle golden failed")

    archive = supplied.get("csbuflo-cpsp-trace-archive")
    archive_record: dict[str, Any] | None = None
    if archive is not None:
        audit = audit_csbuflo_archive(archive)
        if (
            audit.total_records != 4_000
            or audit.included_records != 3_824
            or audit.zero_baseline_records != 176
            or audit.defended_bytes != 7_592_598_380
            or audit.baseline_bytes != 3_326_013_453
            or not abs(audit.bandwidth_ratio - 2.282792444255336) < 1e-12
        ):
            raise ValueError("CS-BuFLO archive aggregate conformance failed")
        archive_record = {
            "defended_bytes": audit.defended_bytes,
            "baseline_bytes": audit.baseline_bytes,
            "total_records": audit.total_records,
            "included_records": audit.included_records,
            "zero_baseline_records": audit.zero_baseline_records,
            "bandwidth_ratio": audit.bandwidth_ratio,
        }
    records.append(
        {
            "oracle_goldens": {
                "buflo_profiles": len(BUFLO_PROFILES),
                "buflo_emission_counts": golden_counts,
                "csbuflo_seeded_jitter": list(jitter_a),
                "csbuflo_archive": archive_record,
            }
        }
    )
    return tuple(records)


def validate_parameters() -> tuple[dict[str, str], ...]:
    records = []
    seen: set[Path] = set()
    for kind, path in PARAMETER_FILES.values():
        if path in seen:
            continue
        seen.add(path)
        artifact = validate_parameter_artifact(
            path,
            expected_kind=kind,
            allow_study_candidate=True,
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
        )
        records.append(
            {
                "kind": kind,
                "path": str(artifact.path),
                "sha256": artifact.sha256,
                "provenance_path": str(artifact.provenance_path),
                "provenance_sha256": artifact.provenance_sha256,
                "input_policy": artifact.input_policy,
            }
        )
    return tuple(records)


def validate_historical_corpus_guard(
    plan: Mapping[str, Any] | None = None, *, deep: bool = True
) -> dict[str, Any]:
    """Verify the frozen historical handoff without rewriting any corpus byte."""

    resolved_plan = load_study_plan() if plan is None else plan
    guard = resolved_plan["historical_corpus_guard"]
    root = (LAB_ROOT / guard["root"]).resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"historical corpus guard root is invalid: {root}")
    for relative, expected in guard["files"].items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise ValueError(f"historical corpus guard digest changed: {relative}")
    exporter = guard["historical_exporter"]
    exporter_path = (LAB_ROOT / exporter["path"]).resolve()
    if (
        exporter_path.is_symlink()
        or not exporter_path.is_file()
        or sha256_file(exporter_path) != exporter["sha256"]
    ):
        raise ValueError("historical classifier exporter changed from its baseline bytes")
    inventory_path = root / "SHA256SUMS"
    inventory: dict[str, str] = {}
    for line in inventory_path.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative in inventory
        ):
            raise ValueError("historical corpus SHA256SUMS is malformed")
        inventory[relative] = digest
    actual: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"historical corpus contains a symlink: {path}")
        if path.is_file() and path != inventory_path:
            actual[path.relative_to(root).as_posix()] = path
    if set(inventory) != set(actual):
        raise ValueError("historical corpus SHA256SUMS is not a closed inventory")
    if deep:
        for relative, expected in inventory.items():
            if sha256_file(actual[relative]) != expected:
                raise ValueError(f"historical corpus evidence changed: {relative}")
    return {
        "root": str(root),
        "sha256sums_sha256": guard["files"]["SHA256SUMS"],
        "dataset_sha256": guard["files"]["dataset.json"],
        "samples_sha256": guard["files"]["samples.jsonl"],
        "historical_exporter": {
            "path": str(exporter_path),
            "sha256": exporter["sha256"],
        },
        "inventory_files": len(inventory),
        "closed_inventory_valid": True,
        "content_hashes_valid": deep,
    }


def _create_only_json(path: Path, value: Any) -> Path:
    """Durably publish a JSON receipt without replacing an existing path."""

    path = path.absolute()
    parent = path.parent.resolve()
    if path.parent.resolve() != parent or parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"create-only receipt parent is invalid: {parent}")
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"create-only receipt already exists: {path}")
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = parent / f".{path.name}.{os.getpid()}.qcsd-tmp"
    try:
        with temporary.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise FileExistsError(f"create-only receipt already exists: {path}") from error
    finally:
        temporary.unlink(missing_ok=True)
    return path


def _file_binding(path: Path) -> dict[str, str]:
    candidate = path.absolute()
    if candidate.is_symlink():
        raise ValueError(f"evidence binding cannot be a symlink: {candidate}")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise ValueError(f"evidence binding is not a regular file: {resolved}")
    return {"path": str(resolved), "sha256": sha256_file(resolved)}


def _portable_lab_path(path: Path) -> str:
    """Project one checkout path onto the canonical `/lab` evidence mount."""

    resolved = Path(os.path.abspath(path)).resolve()
    if not resolved.is_relative_to(LAB_ROOT):
        raise ValueError("historical evidence path is outside the Lab checkout")
    return str(Path("/lab") / resolved.relative_to(LAB_ROOT))


def _resolve_portable_lab_path(value: Any, *, label: str) -> Path:
    """Resolve a canonical `/lab` receipt path in the inspecting checkout."""

    if not isinstance(value, str):
        raise ValueError(f"{label} path is invalid")
    portable = Path(value)
    if (
        not portable.is_absolute()
        or portable.parts[:2] != ("/", "lab")
        or ".." in portable.parts
    ):
        raise ValueError(f"{label} path is not a canonical /lab path")
    resolved = (LAB_ROOT / Path(*portable.parts[2:])).resolve()
    if not resolved.is_relative_to(LAB_ROOT):
        raise ValueError(f"{label} path escapes the Lab checkout")
    return resolved


def _result_binding(path: Path) -> dict[str, str]:
    candidate = path.absolute()
    if candidate.is_symlink():
        raise ValueError(f"result evidence binding cannot be a symlink: {candidate}")
    resolved = candidate.resolve()
    evidence = resolved / "evidence.sha256"
    if (
        resolved.is_symlink()
        or not resolved.is_dir()
        or evidence.is_symlink()
        or not evidence.is_file()
    ):
        raise ValueError(f"result evidence binding is invalid: {resolved}")
    return {"root": str(resolved), "evidence_sha256": sha256_file(evidence)}


def _formal_campaign_bindings(
    *,
    cohort_version: int = 1,
    create_resolved: bool = False,
) -> list[dict[str, str]]:
    return [
        {
            "path": str(path.resolve()),
            "sha256": sha256_file(path),
        }
        for path in campaign_paths(
            "formal",
            cohort_version=cohort_version,
            create_resolved=create_resolved,
        )
    ]


def _current_build_execution_identity(build: Mapping[str, Any]) -> dict[str, Any]:
    """Project one completed schema-5 receipt into its portable identity."""

    version = _cohort_version(build.get("cohort_version"))
    expected_completion = (
        f"/lab/artifacts/buflo-study/build-completion-v{version}.json"
    )
    completion_path = build.get("completion_path")
    if (
        build.get("schema_version") != 5
        or not isinstance(completion_path, str)
        or Path(completion_path).name != f"build-completion-v{version}.json"
        or not isinstance(build.get("completion_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", build["completion_sha256"]) is None
    ):
        raise ValueError("current build receipt has no completion identity")
    return {
        "cohort_version": version,
        "sha256": build["sha256"],
        "completion_path": expected_completion,
        "completion_sha256": build["completion_sha256"],
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }


def _historical_snapshot_value(
    *,
    phase: str,
    formal_result_roots: Sequence[Path] = (),
    pre_snapshot: Path | None = None,
    cohort_version: int = 1,
    create_resolved_campaigns: bool = False,
    _schema_version: int = 2,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    version = _cohort_version(cohort_version)
    if _schema_version not in {1, 2}:
        raise ValueError("historical corpus snapshot schema is invalid")
    historical_schema = _schema_version == 1
    if phase not in {"pre-formal", "post-formal"}:
        raise ValueError("historical snapshot phase must be pre-formal or post-formal")
    source = _expected_clean_collection_source(
        _expected_collection_source,
        label=f"historical {phase} snapshot",
    )
    _validate_clean_source(source, label=f"historical {phase} snapshot")
    selected_build = validate_build_execution_receipt(
        build_execution_receipt_path(version),
        expected_collection_image=source["image_digest"],
        expected_cohort_version=version,
        allow_historical=historical_schema,
    )
    selected_build_binding = {
        "path": selected_build["path"],
        "sha256": selected_build["sha256"],
    }
    result_bindings: list[dict[str, str]] = []
    pre_binding = None
    if phase == "pre-formal":
        if formal_result_roots or pre_snapshot is not None:
            raise ValueError("pre-formal snapshot cannot bind formal results or another snapshot")
    else:
        if pre_snapshot is None or len(formal_result_roots) != 10:
            raise ValueError("post-formal snapshot requires the pre snapshot and ten formal roots")
        pre = validate_historical_guard_snapshot(
            pre_snapshot,
            phase="pre-formal",
            expected_cohort_version=version,
            allow_historical=historical_schema,
        )
        if pre["source"] != source or pre["build_execution_receipt"] != selected_build_binding:
            raise ValueError("pre/post historical snapshots do not share one source/image")
        from .buflo_handoff import _validate_source_results
        from .verification import verify_result

        verified = tuple(verify_result(Path(root)) for root in formal_result_roots)
        _validate_source_results(verified, formal=True)
        if any(receipt.experiment.get("source") != source for receipt in verified):
            raise ValueError("formal results do not share the historical snapshot source")
        result_bindings = [_result_binding(receipt.root) for receipt in verified]
        pre_binding = _file_binding(pre_snapshot)
    guard = validate_historical_corpus_guard(deep=True)
    value = {
        "schema_version": _schema_version,
        "artifact_type": HISTORICAL_SNAPSHOT_ARTIFACT_TYPE,
        "phase": phase,
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
        "study_plan": _file_binding(STUDY_PLAN),
        "source": source,
        "build_execution_receipt": selected_build_binding,
        "formal_campaigns": _formal_campaign_bindings(
            cohort_version=version,
            create_resolved=create_resolved_campaigns,
        ),
        "historical_corpus_guard": guard,
        "historical_corpus_guard_sha256": _canonical_digest(guard),
        "pre_formal_snapshot": pre_binding,
        "formal_results": result_bindings,
    }
    if not historical_schema:
        value["build_execution"] = _current_build_execution_identity(selected_build)
    return value


def create_historical_guard_snapshot(
    destination: Path,
    *,
    phase: str,
    formal_result_roots: Sequence[Path] = (),
    pre_snapshot: Path | None = None,
    cohort_version: int = 1,
) -> Path:
    """Create an immutable before/after proof for the sealed historical corpus."""

    value = _historical_snapshot_value(
        phase=phase,
        formal_result_roots=formal_result_roots,
        pre_snapshot=pre_snapshot,
        cohort_version=cohort_version,
        create_resolved_campaigns=True,
    )
    output = _create_only_json(destination, value)
    validate_historical_guard_snapshot(
        output,
        phase=phase,
        formal_result_roots=formal_result_roots,
        pre_snapshot=pre_snapshot,
        expected_cohort_version=cohort_version,
    )
    return output


def validate_historical_guard_snapshot(
    path: Path,
    *,
    phase: str,
    formal_result_roots: Sequence[Path] = (),
    pre_snapshot: Path | None = None,
    expected_cohort_version: int | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Re-run the historical guard and require an exact derived snapshot."""

    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    if not isinstance(value, dict):
        raise ValueError("historical corpus snapshot is not an object")
    schema_version = value.get("schema_version")
    if schema_version not in {1, 2}:
        raise ValueError("historical corpus snapshot schema is invalid")
    if schema_version != 2 and not allow_historical:
        raise ValueError("current historical-snapshot admission requires schema 2")
    stored_version = _cohort_version(value.get("cohort_version"))
    if expected_cohort_version is not None and stored_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("historical snapshot cohort version does not match the request")
    if phase == "post-formal" and not formal_result_roots:
        formal = value.get("formal_results")
        if not isinstance(formal, list):
            raise ValueError("post-formal snapshot result bindings are invalid")
        formal_result_roots = tuple(
            Path(item["root"]) for item in formal if isinstance(item, Mapping)
        )
    if phase == "post-formal" and pre_snapshot is None:
        pre = value.get("pre_formal_snapshot")
        if not isinstance(pre, Mapping) or not isinstance(pre.get("path"), str):
            raise ValueError("post-formal snapshot has no pre-formal binding")
        pre_snapshot = Path(pre["path"])
    expected = _historical_snapshot_value(
        phase=phase,
        formal_result_roots=formal_result_roots,
        pre_snapshot=pre_snapshot,
        cohort_version=stored_version,
        create_resolved_campaigns=False,
        _schema_version=schema_version,
        _expected_collection_source=(
            value.get("source") if schema_version == 1 and allow_historical else None
        ),
    )
    if value != expected:
        raise ValueError("historical corpus snapshot differs from independently derived evidence")
    return {"path": binding["path"], "sha256": binding["sha256"], **expected}


def _formal_cohort_value(
    *,
    cohort_id: str,
    results_root: Path,
    historical_pre_snapshot: Path,
    cohort_version: int = 1,
    create_resolved_campaigns: bool = False,
    _schema_version: int = 3,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    version = _cohort_version(cohort_version)
    if _schema_version not in {1, 2, 3}:
        raise ValueError("formal cohort manifest schema is invalid")
    historical_schema = _schema_version != 3
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*-v[1-9][0-9]*", cohort_id) is None:
        raise ValueError("formal cohort ID must be a versioned lowercase hyphenated slug")
    if not cohort_id.endswith(f"-v{version}"):
        raise ValueError("formal cohort ID version does not match --cohort-version")
    root_value = results_root.absolute()
    if root_value.is_symlink():
        raise ValueError("formal cohort result root cannot be a symlink")
    results_root = root_value.resolve()
    if not results_root.is_dir():
        raise ValueError("formal cohort result root must already exist")
    source = _expected_clean_collection_source(
        _expected_collection_source,
        label="formal cohort manifest",
    )
    _validate_clean_source(source, label="formal cohort manifest")
    selected_build = validate_build_execution_receipt(
        build_execution_receipt_path(version),
        expected_collection_image=source["image_digest"],
        expected_cohort_version=version,
        allow_historical=historical_schema,
    )
    selected_build_binding = {
        "path": selected_build["path"],
        "sha256": selected_build["sha256"],
    }
    historical = validate_historical_guard_snapshot(
        historical_pre_snapshot,
        phase="pre-formal",
        expected_cohort_version=version,
        allow_historical=historical_schema,
    )
    if (
        historical["source"] != source
        or historical["build_execution_receipt"] != selected_build_binding
    ):
        raise ValueError("formal cohort and pre-formal historical snapshot source differ")
    campaigns = []
    for index, path in enumerate(
        campaign_paths(
            "formal",
            cohort_version=version,
            create_resolved=create_resolved_campaigns,
        )
    ):
        campaign = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(campaign, Mapping) or not isinstance(campaign.get("name"), str):
            raise ValueError("formal cohort campaign identity is invalid")
        run_id = f"{cohort_id}-block-{index + 1:02d}"
        result_root = (results_root / campaign["name"] / run_id).absolute()
        if not result_root.resolve().is_relative_to(results_root):
            raise ValueError("formal cohort result path escapes the result root")
        campaigns.append(
            {
                "block": index + 1,
                "campaign_path": str(path.resolve()),
                "campaign_sha256": sha256_file(path),
                "base_campaign_path": str((CAMPAIGN_ROOT / path.name).resolve()),
                "base_campaign_sha256": sha256_file(CAMPAIGN_ROOT / path.name),
                "campaign_name": campaign["name"],
                "run_id": run_id,
                "result_root": str(result_root),
            }
        )
    implementation_files = (
        "src/qcsd_lab/buflo_study.py",
        "src/qcsd_lab/buflo_handoff.py",
        "src/qcsd_lab/buflo_evaluation.py",
        "src/qcsd_lab/fidelity.py",
        "src/qcsd_lab/parameters.py",
        "src/qcsd_lab/orchestrator.py",
    )
    value = {
        "schema_version": _schema_version,
        "artifact_type": COHORT_MANIFEST_ARTIFACT_TYPE,
        "cohort_id": cohort_id,
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
        "study_plan": _file_binding(STUDY_PLAN),
        "source": source,
        "build_execution_receipt": selected_build_binding,
        "results_root": str(results_root),
        "historical_pre_formal_snapshot": _file_binding(historical_pre_snapshot),
        "formal_campaigns": campaigns,
        "implementation_files": {
            relative: sha256_file(LAB_ROOT / relative) for relative in implementation_files
        },
        "parameter_artifacts": list(validate_parameters()),
        "selection_policy": (
            "prospective-create-only-one-root-per-formal-block;"
            "failed-and-incomplete-roots-retained-and-resumed-never-replaced"
        ),
    }
    formal_evaluation = formal_evaluation_contract_for_cohort(version)
    if formal_evaluation is not None:
        value["formal_evaluation"] = formal_evaluation
    if not historical_schema:
        value["build_execution"] = _current_build_execution_identity(selected_build)
    return value


def create_formal_cohort_manifest(
    destination: Path,
    *,
    cohort_id: str,
    results_root: Path,
    historical_pre_snapshot: Path,
    cohort_version: int = 1,
) -> Path:
    """Prospectively select the only admissible result root for each formal block."""

    version = _cohort_version(cohort_version)
    if version < FORMAL_FAIL_CLOSED_COHORT_VERSION:
        raise ValueError(
            "new formal cohort creation requires cohort version "
            f"{FORMAL_FAIL_CLOSED_COHORT_VERSION} or later"
        )
    value = _formal_cohort_value(
        cohort_id=cohort_id,
        results_root=results_root,
        historical_pre_snapshot=historical_pre_snapshot,
        cohort_version=version,
        create_resolved_campaigns=True,
    )
    if any(Path(row["result_root"]).exists() for row in value["formal_campaigns"]):
        raise FileExistsError("formal cohort creation requires all ten selected roots to be absent")
    output = _create_only_json(destination, value)
    validate_formal_cohort_manifest(output, allow_existing_results=False)
    return output


def validate_formal_cohort_manifest(
    path: Path,
    *,
    allow_existing_results: bool = True,
    expected_cohort_version: int | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    if not isinstance(value, Mapping):
        raise ValueError("formal cohort manifest is not an object")
    schema_version = value.get("schema_version")
    if schema_version not in {1, 2, 3}:
        raise ValueError("formal cohort manifest schema is invalid")
    if schema_version != 3 and not allow_historical:
        raise ValueError("current formal-cohort admission requires schema 3")
    stored_version = _cohort_version(value.get("cohort_version"))
    if expected_cohort_version is not None and stored_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("formal cohort version does not match the request")
    pre = value.get("historical_pre_formal_snapshot")
    if not isinstance(pre, Mapping) or not isinstance(pre.get("path"), str):
        raise ValueError("formal cohort has no pre-formal historical snapshot")
    expected = _formal_cohort_value(
        cohort_id=str(value.get("cohort_id")),
        results_root=Path(str(value.get("results_root"))),
        historical_pre_snapshot=Path(pre["path"]),
        cohort_version=stored_version,
        _schema_version=schema_version,
        _expected_collection_source=(
            value.get("source") if schema_version in {1, 2} and allow_historical else None
        ),
    )
    if value != expected:
        raise ValueError("formal cohort manifest differs from prospectively derived inputs")
    from .verification import verify_result

    observed_roots = []
    for row in expected["formal_campaigns"]:
        root = Path(row["result_root"])
        if root.is_symlink():
            raise ValueError("formal cohort selected result root cannot be a symlink")
        if not root.exists():
            continue
        if not allow_existing_results:
            raise ValueError("formal cohort selected result root was not absent at freeze time")
        if not root.is_dir():
            raise ValueError("formal cohort selected result root is not a directory")
        experiment_path = root / "experiment.json"
        if experiment_path.is_symlink() or not experiment_path.is_file():
            raise ValueError("formal cohort root has no authoritative experiment checkpoint")
        experiment = load_json(experiment_path)
        if (
            not isinstance(experiment, Mapping)
            or experiment.get("name") != row["campaign_name"]
            or experiment.get("source") != expected["source"]
            or experiment.get("configuration", {}).get("campaign_sha256") != row["campaign_sha256"]
        ):
            raise ValueError("formal cohort root differs from its prospective block binding")
        if (root / "evidence.sha256").is_file():
            verify_result(root)
        observed_roots.append(str(root))
    return {
        "path": binding["path"],
        "sha256": binding["sha256"],
        **expected,
        "observed_result_roots": observed_roots,
    }


def formal_cohort_result_root(manifest: Path, campaign_path: Path) -> Path:
    """Resolve one checked-in formal campaign to its sole prospective result root."""

    cohort = validate_formal_cohort_manifest(manifest)
    resolved_campaign = campaign_path.resolve()
    matches = [
        row
        for row in cohort["formal_campaigns"]
        if Path(row["campaign_path"]) == resolved_campaign
        and row["campaign_sha256"] == sha256_file(resolved_campaign)
    ]
    if len(matches) != 1:
        raise ValueError("formal campaign is not selected by the prospective cohort manifest")
    return Path(matches[0]["result_root"])


def _capture_admission_value(
    *,
    stage: str,
    reference_receipt: Path,
    qualification_receipt: Path,
    prerequisite_result_roots: Sequence[Path],
    results_root: Path,
    formal_cohort_manifest: Path | None = None,
    historical_pre_snapshot: Path | None = None,
    code_gate_receipt: Path | None = None,
    formal_window_hours: float | None = None,
    formal_capacity_record: Mapping[str, Any] | None = None,
    cohort_version: int = 1,
    create_resolved_campaigns: bool = False,
    _schema_version: int = 4,
) -> dict[str, Any]:
    version = _cohort_version(cohort_version)
    if _schema_version not in {1, 2, 3, 4}:
        raise ValueError("capture admission schema is invalid")
    historical_schema = _schema_version != 4
    if stage not in STAGED_CAPTURE_PREREQUISITES:
        raise ValueError("capture admission stage must be smoke, rehearsal, or formal")
    reference = validate_reference_gate_receipt(
        reference_receipt,
        expected_cohort_version=version,
        allow_historical=historical_schema,
    )
    qualification = validate_qualification_receipt(
        qualification_receipt,
        expected_cohort_version=version,
        allow_historical=historical_schema,
    )
    staged = validate_staged_capture_prerequisites(
        stage,
        prerequisite_result_roots,
        expected_cohort_version=version,
    )
    source = staged["source"]
    if qualification["source"] != source:
        raise ValueError("qualification and staged capture prerequisites use different images")
    selected_build = validate_build_execution_receipt(
        build_execution_receipt_path(version),
        expected_collection_image=source["image_digest"],
        expected_cohort_version=version,
        allow_historical=historical_schema,
    )
    selected_build_binding = {
        "path": selected_build["path"],
        "sha256": selected_build["sha256"],
    }
    build_environments = [
        record["environment"] for record in qualification["controlled_results"]["results"]
    ]
    build_environments.extend(record["environment"] for record in staged["regression"]["results"])
    build_environments.extend(record["environment"] for record in staged["public"].values())
    capture_scheduler = None
    if version >= 9:
        expected_scheduler = _capture_scheduler_environment_contract()
        if any(
            environment.get("schema_version") != (2 if historical_schema else 3)
            or environment.get("capture_scheduler") != expected_scheduler
            or environment.get("docker", {}).get("ncpu") != 12
            for environment in build_environments
        ):
            raise ValueError("capture admission requires one exact 12-CPU RR1 affinity contract")
        capture_scheduler = {
            "docker_ncpu": 12,
            **expected_scheduler,
        }
    build_execution = _one_build_execution_identity(
        build_environments, allow_historical=historical_schema
    )
    expected_build_execution = (
        {
            "cohort_version": version,
            "sha256": selected_build["sha256"],
            "collection_image": selected_build["collection_image"],
            "started_at": selected_build["started_at"],
            "finished_at": selected_build["finished_at"],
        }
        if historical_schema
        else _current_build_execution_identity(selected_build)
    )
    if (
        build_execution != expected_build_execution
        or reference.get("build_execution") != expected_build_execution
        or qualification.get("build_execution") != selected_build_binding
    ):
        raise ValueError("reference/qualification/capture did not use one no-cache build")
    root_value = results_root.absolute()
    if root_value.is_symlink():
        raise ValueError("capture admission result root cannot be a symlink")
    results_root = root_value.resolve()
    if not results_root.is_dir():
        raise ValueError("capture admission result root must already exist")
    capacity = None
    cohort = None
    historical = None
    code_gate = None
    if stage == "formal":
        if formal_cohort_manifest is None or historical_pre_snapshot is None:
            raise ValueError("formal admission requires cohort and pre-formal snapshot receipts")
        if version >= FORMAL_FAIL_CLOSED_COHORT_VERSION and code_gate_receipt is None:
            raise ValueError("formal admission requires a validated code-gate receipt")
        if code_gate_receipt is not None:
            regression_rows = staged.get("regression", {}).get("results", [])
            regression_roots = tuple(
                Path(row["root"])
                for row in regression_rows
                if isinstance(row, Mapping) and isinstance(row.get("root"), str)
            )
            code_gate = validate_code_gate_receipt(
                code_gate_receipt,
                regression_result_roots=regression_roots,
                expected_cohort_version=version,
                deep=False,
                allow_historical=historical_schema,
            )
            if (
                code_gate["source"] != source
                or code_gate["build_execution_receipt"] != selected_build_binding
                or code_gate["live_regression"] != staged["regression"]
            ):
                raise ValueError("formal admission code gate differs from staged evidence")
        historical = validate_historical_guard_snapshot(
            historical_pre_snapshot,
            phase="pre-formal",
            expected_cohort_version=version,
            allow_historical=historical_schema,
        )
        cohort = validate_formal_cohort_manifest(
            formal_cohort_manifest,
            expected_cohort_version=version,
            allow_historical=historical_schema,
        )
        if (
            cohort["cohort_version"] != version
            or cohort["qualification_set"] != qualification_set_for_cohort(version)
            or historical["source"] != source
            or cohort["source"] != source
            or cohort["historical_pre_formal_snapshot"] != _file_binding(historical_pre_snapshot)
            or Path(cohort["results_root"]) != results_root
        ):
            raise ValueError("formal cohort/history/staged source lineage differs")
        if formal_capacity_record is None:
            capacity = validate_formal_capture_capacity(
                staged,
                available_window_hours=formal_window_hours,
                results_root=results_root,
            )
        else:
            capacity = _validate_formal_capture_capacity_record(
                staged,
                formal_capacity_record,
                available_window_hours=formal_window_hours,
                results_root=results_root,
            )
        allowed = [dict(row) for row in cohort["formal_campaigns"]]
    else:
        if (
            formal_cohort_manifest is not None
            or historical_pre_snapshot is not None
            or code_gate_receipt is not None
        ):
            raise ValueError(
                "non-formal admission cannot bind formal cohort/history/code-gate receipts"
            )
        selected = campaign_paths(
            stage,
            cohort_version=version,
            create_resolved=create_resolved_campaigns,
        )
        allowed = []
        for path in selected:
            campaign = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(campaign, Mapping) or not isinstance(campaign.get("name"), str):
                raise ValueError("capture admission campaign identity is invalid")
            run_id = f"buflo-study-{stage}-admitted-v{version}"
            allowed.append(
                {
                    "block": None,
                    "campaign_path": str(path.resolve()),
                    "campaign_sha256": sha256_file(path),
                    "base_campaign_path": str((CAMPAIGN_ROOT / path.name).resolve()),
                    "base_campaign_sha256": sha256_file(CAMPAIGN_ROOT / path.name),
                    "campaign_name": campaign["name"],
                    "run_id": run_id,
                    "result_root": str((results_root / campaign["name"] / run_id).absolute()),
                }
            )
    if any(
        not Path(row["result_root"]).resolve(strict=False).is_relative_to(results_root)
        or Path(row["result_root"]).parents[1] != results_root
        for row in allowed
    ):
        raise ValueError("capture admission selected result root escapes its bound results root")
    legacy_schema = 3 if code_gate is not None else (2 if capture_scheduler is not None else 1)
    if historical_schema and _schema_version != legacy_schema:
        raise ValueError("historical capture admission schema/features differ")
    value = {
        "schema_version": _schema_version,
        "artifact_type": CAPTURE_ADMISSION_ARTIFACT_TYPE,
        "stage": stage,
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
        "results_root": str(results_root),
        "study_plan": _file_binding(STUDY_PLAN),
        "source": source,
        "build_execution_receipt": selected_build_binding,
        "build_execution": build_execution,
        "reference_gate": reference,
        "qualification": qualification,
        "staged_prerequisites": staged,
        "historical_pre_formal_snapshot": (
            _file_binding(historical_pre_snapshot) if historical_pre_snapshot is not None else None
        ),
        "formal_cohort": (
            _file_binding(formal_cohort_manifest) if formal_cohort_manifest is not None else None
        ),
        "formal_capacity": capacity,
        "allowed_campaigns": allowed,
        "serial_acquisition_required": True,
        "resume_policy": "resume-only-the-selected-experiment-json-root;never-create-a-replacement",
        "passed": True,
    }
    if capture_scheduler is not None:
        value["capture_scheduler"] = capture_scheduler
    if code_gate is not None:
        value["code_gate"] = code_gate
    return value


def create_capture_admission(
    destination: Path,
    *,
    stage: str,
    reference_receipt: Path,
    qualification_receipt: Path,
    prerequisite_result_roots: Sequence[Path],
    results_root: Path,
    formal_cohort_manifest: Path | None = None,
    historical_pre_snapshot: Path | None = None,
    code_gate_receipt: Path | None = None,
    formal_window_hours: float | None = None,
    cohort_version: int = 1,
) -> Path:
    """Create the only token from which a public study capture may launch."""

    version = _cohort_version(cohort_version)
    if stage == "formal" and version < FORMAL_FAIL_CLOSED_COHORT_VERSION:
        raise ValueError(
            "new formal capture admission requires cohort version "
            f"{FORMAL_FAIL_CLOSED_COHORT_VERSION} or later"
        )
    value = _capture_admission_value(
        stage=stage,
        reference_receipt=reference_receipt,
        qualification_receipt=qualification_receipt,
        prerequisite_result_roots=prerequisite_result_roots,
        results_root=results_root,
        formal_cohort_manifest=formal_cohort_manifest,
        historical_pre_snapshot=historical_pre_snapshot,
        code_gate_receipt=code_gate_receipt,
        formal_window_hours=formal_window_hours,
        formal_capacity_record=None,
        cohort_version=version,
        create_resolved_campaigns=True,
    )
    if any(Path(row["result_root"]).exists() for row in value["allowed_campaigns"]):
        raise FileExistsError("new capture admission requires every selected result root absent")
    output = _create_only_json(destination, value)
    validate_capture_admission(output, allow_existing_results=False)
    return output


def validate_capture_admission(
    path: Path,
    *,
    allow_existing_results: bool = True,
    expected_cohort_version: int | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    if not isinstance(value, Mapping):
        raise ValueError("capture admission is not an object")
    stored_version = _cohort_version(value.get("cohort_version"))
    if expected_cohort_version is not None and stored_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("capture admission cohort version does not match the request")
    schema_version = value.get("schema_version")
    if schema_version not in {1, 2, 3, 4}:
        raise ValueError("capture admission schema is invalid")
    if schema_version != 4 and not allow_historical:
        raise ValueError("current capture admission requires schema 4")
    reference = value.get("reference_gate")
    qualification = value.get("qualification")
    staged = value.get("staged_prerequisites")
    if not all(isinstance(item, Mapping) for item in (reference, qualification, staged)):
        raise ValueError("capture admission typed evidence is incomplete")
    prerequisite_roots = []
    regression = staged.get("regression")
    if isinstance(regression, Mapping):
        prerequisite_roots.extend(
            Path(item["root"])
            for item in regression.get("results", [])
            if isinstance(item, Mapping)
        )
    public = staged.get("public")
    if isinstance(public, Mapping):
        prerequisite_roots.extend(
            Path(item["root"])
            for item in public.values()
            if isinstance(item, Mapping) and isinstance(item.get("root"), str)
        )
    historical = value.get("historical_pre_formal_snapshot")
    cohort = value.get("formal_cohort")
    code_gate = value.get("code_gate")
    expected = _capture_admission_value(
        stage=str(value.get("stage")),
        reference_receipt=Path(str(reference.get("path"))),
        qualification_receipt=Path(str(qualification.get("path"))),
        prerequisite_result_roots=tuple(prerequisite_roots),
        results_root=Path(str(value.get("results_root"))),
        formal_cohort_manifest=(Path(cohort["path"]) if isinstance(cohort, Mapping) else None),
        historical_pre_snapshot=(
            Path(historical["path"]) if isinstance(historical, Mapping) else None
        ),
        code_gate_receipt=(Path(code_gate["path"]) if isinstance(code_gate, Mapping) else None),
        formal_window_hours=(
            value.get("formal_capacity", {}).get("available_window_hours")
            if isinstance(value.get("formal_capacity"), Mapping)
            else None
        ),
        formal_capacity_record=(
            value.get("formal_capacity")
            if isinstance(value.get("formal_capacity"), Mapping)
            else None
        ),
        cohort_version=stored_version,
        create_resolved_campaigns=False,
        _schema_version=schema_version,
    )
    if value != expected:
        raise ValueError("capture admission differs from independently derived evidence")
    for row in expected["allowed_campaigns"]:
        root = Path(row["result_root"])
        if root.is_symlink():
            raise ValueError("capture admission selected result cannot be a symlink")
        if root.exists() and not allow_existing_results:
            raise ValueError("capture admission selected result was not absent at admission")
        if root.exists() and not root.is_dir():
            raise ValueError("capture admission selected result is not a directory")
    return {"path": binding["path"], "sha256": binding["sha256"], **expected}


def admitted_result_root(
    admission: Path,
    campaign_path: Path,
    *,
    require_sequence: bool = False,
) -> Path:
    admission_value = validate_capture_admission(admission)
    resolved = campaign_path.resolve()
    matches = [
        row
        for row in admission_value["allowed_campaigns"]
        if Path(row["campaign_path"]) == resolved
        and row["campaign_sha256"] == sha256_file(resolved)
    ]
    if len(matches) != 1:
        raise ValueError("campaign is not authorized by the capture admission")
    if require_sequence and admission_value["stage"] == "formal":
        from .verification import verify_result

        selected_index = admission_value["allowed_campaigns"].index(matches[0])
        for row in admission_value["allowed_campaigns"][:selected_index]:
            root = Path(row["result_root"])
            if not root.is_dir() or not (root / "evidence.sha256").is_file():
                raise ValueError("formal blocks must launch in prospective chronological order")
            verified = verify_result(root)
            if verified.experiment.get("status") != "complete":
                raise ValueError("prior formal block is not complete and sealed")
        if any(
            Path(row["result_root"]).exists()
            for row in admission_value["allowed_campaigns"][selected_index + 1 :]
        ):
            raise ValueError("a later formal block exists before the selected block completed")
        capacity = admission_value.get("formal_capacity")
        if not isinstance(capacity, Mapping):
            raise ValueError("formal admission has no frozen capacity evidence")
        projected = capacity.get("projected_formal_bytes")
        if type(projected) is not int or projected <= 0:
            raise ValueError("formal admission projected storage is invalid")
        remaining_blocks = len(admission_value["allowed_campaigns"]) - selected_index
        remaining_authoritative = math.ceil(
            projected * remaining_blocks / len(admission_value["allowed_campaigns"])
        )
        results_root = Path(admission_value["results_root"])
        current_free = shutil.disk_usage(results_root).free
        if current_free < 3 * remaining_authoritative:
            raise ValueError(
                "current result storage no longer has the required 3x remaining-formal "
                "safety margin"
            )
    return Path(matches[0]["result_root"])


def _qualification_build_binding(
    cohort_version: int = 1,
    *,
    allow_historical: bool = False,
) -> tuple[dict[str, Any], str]:
    version = _cohort_version(cohort_version)
    receipt = validate_build_execution_receipt(
        build_execution_receipt_path(version),
        expected_cohort_version=version,
        allow_historical=allow_historical,
    )
    binding = {"path": receipt["path"], "sha256": receipt["sha256"]}
    build = receipt
    prepare_image_id = build["images"]["prepare"]["id"]
    return binding, prepare_image_id


def qualification_status(
    result_roots: Sequence[Path] = (),
    *,
    require_controlled: bool = True,
    cohort_version: int = 1,
    allow_historical: bool = False,
) -> tuple[bool, str]:
    version = _cohort_version(cohort_version)
    root = QUALIFICATION_SET_ROOT / qualification_set_for_cohort(version)
    expected = {f"{workload}.json" for workload in WORKLOADS}
    if root.is_symlink() or not root.is_dir():
        return False, f"qualification set is absent: {root}"
    children = tuple(root.iterdir())
    if {path.name for path in children} != expected or any(
        path.is_symlink() or not path.is_file() for path in children
    ):
        return False, f"qualification set does not contain the exact five sidecars: {root}"
    from .chaff_qualification import (
        RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        load_response_qualified_chaff,
    )

    try:
        _build_binding, prepare_image_id = _qualification_build_binding(
            version, allow_historical=allow_historical
        )
    except (OSError, ValueError) as error:
        return False, f"sustained chaff qualification has no valid build execution: {error}"
    for workload in WORKLOADS:
        try:
            sidecar_path = root / f"{workload}.json"
            load_response_qualified_chaff(
                sidecar_path,
                workload_id=workload,
                base_manifest_path=LAB_ROOT / f"config/workloads/{workload}.json",
                expected_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
                require_current_implementation=True,
            )
            sidecar = load_json(sidecar_path)
            if sidecar.get("qualification_image_digest") != prepare_image_id:
                raise ValueError(
                    "qualification image differs from the exact no-cache prepare image"
                )
        except (OSError, ValueError) as error:
            return False, f"sustained chaff qualification is invalid for {workload}: {error}"
    if not require_controlled:
        return True, f"{root}; exact sustained chaff sidecars verified"
    if not result_roots:
        return False, "controlled 160-sample qualification evidence has not been supplied"
    try:
        controlled = validate_controlled_results(result_roots)
    except (OSError, ValueError) as error:
        return False, f"controlled 160-sample qualification evidence is invalid: {error}"
    return True, f"{root}; {controlled['samples']} controlled samples verified"


def _qualification_receipt_value(
    controlled_result_roots: Sequence[Path],
    *,
    explanation_receipt: Path | None = None,
    cohort_version: int = 1,
    _expected_collection_source: Mapping[str, Any] | None = None,
    _schema_version: int = 2,
) -> dict[str, Any]:
    version = _cohort_version(cohort_version)
    if _schema_version not in {1, 2}:
        raise ValueError("qualification receipt schema is invalid")
    historical = _schema_version == 1
    ready, status = qualification_status(
        require_controlled=False,
        cohort_version=version,
        allow_historical=historical,
    )
    if not ready:
        raise ValueError(status)
    controlled = validate_controlled_results(
        controlled_result_roots,
        explanation_receipt=explanation_receipt,
        _expected_collection_source=_expected_collection_source,
    )
    if (
        controlled.get("samples") != 160
        or controlled.get("sustained_cell_capacity", {}).get("passed") is not True
        or controlled.get("ctsp_cpsp_ordering", {}).get("passed") is not True
    ):
        raise ValueError("qualification receipt requires every controlled hard gate")
    build_binding, prepare_image_id = _qualification_build_binding(
        version, allow_historical=historical
    )
    controlled_build = _one_build_execution_identity(
        [record["environment"] for record in controlled["results"]],
        allow_historical=historical,
    )
    selected_build = validate_build_execution_receipt(
        Path(build_binding["path"]),
        expected_collection_image=controlled["source"]["image_digest"],
        expected_cohort_version=version,
        allow_historical=historical,
    )
    expected_build_identity = (
        {
            "cohort_version": version,
            "sha256": selected_build["sha256"],
            "collection_image": selected_build["collection_image"],
            "started_at": selected_build["started_at"],
            "finished_at": selected_build["finished_at"],
        }
        if historical
        else _current_build_execution_identity(selected_build)
    )
    if controlled_build != expected_build_identity:
        raise ValueError("controlled qualification did not use the exact no-cache build execution")
    set_root = QUALIFICATION_SET_ROOT / qualification_set_for_cohort(version)
    sidecars = [_file_binding(set_root / f"{workload}.json") for workload in WORKLOADS]
    return {
        "schema_version": _schema_version,
        "artifact_type": QUALIFICATION_RECEIPT_ARTIFACT_TYPE,
        "cohort_version": version,
        "study_plan": _file_binding(STUDY_PLAN),
        "build_execution": build_binding,
        "prepare_image_id": prepare_image_id,
        "qualification_set": {
            "name": qualification_set_for_cohort(version),
            "root": str(set_root.resolve()),
            "sidecars": sidecars,
            "status": status,
        },
        "parameter_artifacts": list(validate_parameters()),
        "controlled_results": controlled,
        "source": controlled["source"],
        "passed": True,
    }


def create_qualification_receipt(
    destination: Path,
    controlled_result_roots: Sequence[Path],
    *,
    explanation_receipt: Path | None = None,
    cohort_version: int = 1,
) -> Path:
    """Create the immutable sustained-chaff plus controlled-capacity receipt."""

    value = _qualification_receipt_value(
        controlled_result_roots,
        explanation_receipt=explanation_receipt,
        cohort_version=cohort_version,
    )
    output = _create_only_json(destination, value)
    validate_qualification_receipt(
        output,
        controlled_result_roots=controlled_result_roots,
        explanation_receipt=explanation_receipt,
        expected_cohort_version=cohort_version,
    )
    return output


def validate_qualification_receipt(
    path: Path,
    *,
    controlled_result_roots: Sequence[Path] = (),
    explanation_receipt: Path | None = None,
    expected_cohort_version: int | None = None,
    _expected_collection_source: Mapping[str, Any] | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    if not isinstance(value, Mapping):
        raise ValueError("qualification receipt is not an object")
    schema_version = value.get("schema_version")
    if schema_version not in {1, 2}:
        raise ValueError("qualification receipt schema is invalid")
    if schema_version != 2 and not allow_historical:
        raise ValueError("current qualification admission requires schema 2")
    if schema_version == 1 and allow_historical and _expected_collection_source is None:
        stored_source = value.get("source")
        _validate_clean_source(stored_source, label="historical qualification receipt")
        _expected_collection_source = dict(stored_source)
    stored_version = _cohort_version(value.get("cohort_version"))
    if expected_cohort_version is not None and stored_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("qualification receipt cohort version does not match the request")
    if not controlled_result_roots:
        controlled = value.get("controlled_results")
        results = controlled.get("results") if isinstance(controlled, Mapping) else None
        if not isinstance(results, list):
            raise ValueError("qualification receipt controlled result bindings are invalid")
        controlled_result_roots = tuple(
            Path(item["root"])
            for item in results
            if isinstance(item, Mapping) and isinstance(item.get("root"), str)
        )
    if explanation_receipt is None:
        ordering = value.get("controlled_results", {}).get("ctsp_cpsp_ordering")
        explanation = (
            ordering.get("reviewed_explanation") if isinstance(ordering, Mapping) else None
        )
        if isinstance(explanation, Mapping) and isinstance(explanation.get("path"), str):
            explanation_receipt = Path(explanation["path"])
    expected = _qualification_receipt_value(
        controlled_result_roots,
        explanation_receipt=explanation_receipt,
        cohort_version=stored_version,
        _expected_collection_source=_expected_collection_source,
        _schema_version=schema_version,
    )
    if value != expected:
        raise ValueError("qualification receipt differs from independently derived evidence")
    return {"path": binding["path"], "sha256": binding["sha256"], **expected}


_RUST_CODE_GATE_COMMANDS = (
    ("cargo-fmt", ("cargo", "fmt", "--check")),
    ("neqo-csdef-tests", ("cargo", "test", "-p", "neqo-csdef", "--locked")),
    (
        "neqo-transport-tests",
        ("cargo", "test", "-p", "neqo-transport", "--features", "qcsd", "--locked"),
    ),
    (
        "neqo-http3-tests",
        ("cargo", "test", "-p", "neqo-http3", "--features", "qcsd", "--locked"),
    ),
    (
        "neqo-bin-tests",
        ("cargo", "test", "-p", "neqo-bin", "--features", "qcsd", "--locked"),
    ),
    (
        "workspace-clippy",
        (
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--features",
            "qcsd",
            "--locked",
            "--",
            "-D",
            "warnings",
        ),
    ),
)
_LAB_CODE_GATE_COMMANDS = (
    (
        "full-lab-suite",
        (
            "python",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
        ),
    ),
    (
        "buflo-schema-handoff-suite",
        (
            "python",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "tests/test_buflo_reference.py",
            "tests/test_buflo_study.py",
            "tests/test_buflo_handoff.py",
            "tests/test_buflo_evaluation.py",
            "tests/test_fidelity.py",
        ),
    ),
)


def _validate_embedded_json_receipt(
    path: Path,
    *,
    expected: Mapping[str, Any],
    claimed_sha256: object,
    label: str,
) -> None:
    """Bind a parsed receipt value to the exact sidecar bytes embedded in the image."""

    unresolved = path.absolute()
    if unresolved.is_symlink() or not unresolved.is_file():
        raise ValueError(f"Rust code-gate {label} sidecar is absent or unsafe")
    data = unresolved.read_bytes()
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Rust code-gate {label} sidecar is invalid JSON") from exc
    if parsed != expected:
        raise ValueError(f"Rust code-gate {label} sidecar content is inconsistent")
    if claimed_sha256 != hashlib.sha256(data).hexdigest():
        raise ValueError(f"Rust code-gate {label} sidecar hash is invalid")


def validate_rust_code_gate(
    root: Path | None = None,
    *,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the immutable build-stage Rust command receipt and every log."""

    if root is None:
        root = RUST_CODE_GATE_ROOT
    unresolved = root.absolute()
    if unresolved.is_symlink():
        raise ValueError("Rust code-gate root cannot be a symlink")
    root = unresolved.resolve()
    receipt_path = root / "receipt.json"
    logs_root = root / "logs"
    if not root.is_dir() or not receipt_path.is_file() or not logs_root.is_dir():
        raise ValueError("Rust code-gate bundle is absent or incomplete")
    value = load_json(receipt_path)
    required = {
        "schema_version",
        "artifact_type",
        "domain",
        "passed",
        "target_arch",
        "dockerfile_frontend",
        "rust_base_image",
        "uv_image",
        "source_metadata",
        "source_metadata_sha256",
        "study_build_inputs",
        "study_build_inputs_sha256",
        "commands",
        "logs",
        "tool_versions",
        "sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-rust-code-gate"
        or value.get("domain") != "qcsd-rust-code-gate-v1"
        or value.get("passed") is not True
        or value.get("rust_base_image") != RUST_BASE_IMAGE
        or value.get("dockerfile_frontend")
        != "docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
        or value.get("uv_image")
        != "ghcr.io/astral-sh/uv:0.10.7@sha256:edd1fd89f3e5b005814cc8f777610445d7b7e3ed05361f9ddfae67bebfe8456a"
        or value.get("target_arch") not in {"amd64", "arm64"}
    ):
        raise ValueError("Rust code-gate receipt identity is invalid")
    commands = [{"gate": gate, "argv": list(argv)} for gate, argv in _RUST_CODE_GATE_COMMANDS]
    if value.get("commands") != commands:
        raise ValueError("Rust code-gate command inventory is not exact")
    logs = value.get("logs")
    if not isinstance(logs, Mapping) or set(logs) != {gate for gate, _ in _RUST_CODE_GATE_COMMANDS}:
        raise ValueError("Rust code-gate log inventory is not exact")
    actual_log_names = {
        path.name for path in logs_root.iterdir() if path.is_file() and not path.is_symlink()
    }
    expected_log_names = {f"{gate}.log" for gate, _ in _RUST_CODE_GATE_COMMANDS}
    if actual_log_names != expected_log_names or any(
        path.is_symlink() for path in logs_root.iterdir()
    ):
        raise ValueError("Rust code-gate log directory is not a closed inventory")
    for gate, _argv in _RUST_CODE_GATE_COMMANDS:
        record = logs[gate]
        path = logs_root / f"{gate}.log"
        data = path.read_bytes()
        if (
            not isinstance(record, Mapping)
            or record.get("path") != f"logs/{gate}.log"
            or record.get("bytes") != len(data)
            or record.get("sha256") != hashlib.sha256(data).hexdigest()
            or not data.endswith(b"status=passed\n")
        ):
            raise ValueError(f"Rust code-gate log is invalid: {gate}")
    collection_source = _expected_clean_collection_source(
        _expected_collection_source,
        label="Rust code-gate collection image",
    )
    expected_build_source = {**collection_source, "image_digest": None}
    if value.get("source_metadata") != expected_build_source:
        raise ValueError("Rust code-gate source does not match the collection image")
    build_inputs = value.get("study_build_inputs")
    if (
        not isinstance(build_inputs, Mapping)
        or build_inputs.get("schema_version") != 1
        or build_inputs.get("artifact_type") != "qcsd-study-build-inputs"
        or build_inputs.get("rust_base_image") != RUST_BASE_IMAGE
        or build_inputs.get("debian_base_image") != DEBIAN_BASE_IMAGE
        or build_inputs.get("uv_lock_sha256") != sha256_file(LAB_ROOT / "uv.lock")
        or build_inputs.get("cargo_lock_sha256") != sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock")
    ):
        raise ValueError("Rust code-gate build-input receipt is invalid")
    # The build receipt hashes the exact metadata files copied into the image.
    # JSON object key order is not semantic and the enclosing receipt is emitted
    # with sorted keys, so reserializing the nested mappings cannot recover those
    # original bytes.  Bind both parsed content and exact sidecar bytes instead.
    _validate_embedded_json_receipt(
        root.parent / "source.json",
        expected=value["source_metadata"],
        claimed_sha256=value.get("source_metadata_sha256"),
        label="source-metadata",
    )
    _validate_embedded_json_receipt(
        root.parent / "study-build-inputs.json",
        expected=build_inputs,
        claimed_sha256=value.get("study_build_inputs_sha256"),
        label="build-input",
    )
    tools = value.get("tool_versions")
    if (
        not isinstance(tools, Mapping)
        or set(tools) != {"cargo", "clippy", "rustc", "rustfmt"}
        or any(not isinstance(item, str) or not item for item in tools.values())
    ):
        raise ValueError("Rust code-gate tool-version receipt is invalid")
    claimed = value["sha256"]
    unsigned = dict(value)
    del unsigned["sha256"]
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    expected_self_hash = hashlib.sha256(value["domain"].encode() + b"\0" + payload).hexdigest()
    if claimed != expected_self_hash:
        raise ValueError("Rust code-gate self-hash is invalid")
    return {
        "root": str(root),
        "receipt_sha256": sha256_file(receipt_path),
        "self_hash": claimed,
        "source": collection_source,
        "commands": commands,
        "passed": True,
    }


def _run_lab_code_gate_commands() -> list[dict[str, Any]]:
    records = []
    for gate, template in _LAB_CODE_GATE_COMMANDS:
        argv = [
            os.fspath(Path(os.sys.executable)) if value == "python" else value for value in template
        ]
        completed = subprocess.run(
            argv,
            cwd=LAB_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        output = completed.stdout or ""
        record = {
            "gate": gate,
            "argv": argv,
            "cwd": str(LAB_ROOT),
            "exit_code": completed.returncode,
            "stdout_bytes": len(output.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "stdout": output,
        }
        records.append(record)
        if completed.returncode != 0:
            raise RuntimeError(f"code gate failed: {gate}\n{output}")
    return records


def _validate_historical_rust_code_gate_summary(
    value: Any, *, source: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the immutable outer binding without requiring its old image."""

    expected_commands = [
        {"gate": gate, "argv": list(argv)} for gate, argv in _RUST_CODE_GATE_COMMANDS
    ]
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {"root", "receipt_sha256", "self_hash", "source", "commands", "passed"}
        or value.get("root") != "/usr/share/qcsd-lab/rust-code-gate"
        or not isinstance(value.get("receipt_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["receipt_sha256"]) is None
        or not isinstance(value.get("self_hash"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["self_hash"]) is None
        or value.get("source") != source
        or value.get("commands") != expected_commands
        or value.get("passed") is not True
    ):
        raise ValueError("historical Rust code-gate summary is invalid")
    return dict(value)


def _validate_historical_result_projection(
    value: Any, *, source: Mapping[str, Any]
) -> dict[str, Any]:
    """Rebuild a sealed historical result summary without current semantics.

    Current sample-schema rules cannot be retroactively applied to old sealed
    runs.  This branch still checks the closed inventory and every listed byte,
    then derives the exact outer projection from those immutable files.
    """

    expected_keys = {
        "root",
        "name",
        "evidence_sha256",
        "samples",
        "campaign_sha256",
        "authoritative_bytes",
        "environment",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise ValueError("historical regression result binding is invalid")
    root = _resolve_portable_lab_path(value.get("root"), label="historical regression result")
    from .verification import authoritative_files

    evidence = root / "evidence.sha256"
    if evidence.is_symlink() or not evidence.is_file():
        raise ValueError("historical regression result is not sealed")
    raw = evidence.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise ValueError("historical regression checksum inventory is invalid") from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise ValueError("historical regression checksum inventory is invalid")
    checksums: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        digest, separator, relative = line.partition("  ")
        candidate = Path(relative)
        if (
            separator != "  "
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not relative
            or relative in checksums
            or candidate.is_absolute()
            or ".." in candidate.parts
            or candidate.as_posix() != relative
        ):
            raise ValueError("historical regression checksum inventory is invalid")
        checksums[relative] = digest
    files = authoritative_files(root)
    if set(files) != set(checksums) or any(
        sha256_file(files[relative]) != digest for relative, digest in checksums.items()
    ):
        raise ValueError("historical regression authoritative bytes changed")
    experiment = load_json(root / "experiment.json")
    if (
        not isinstance(experiment, Mapping)
        or experiment.get("status") != "complete"
        or experiment.get("source") != source
        or not isinstance(experiment.get("samples"), list)
    ):
        raise ValueError("historical regression experiment identity is invalid")
    accepted = [sample for sample in experiment["samples"] if sample.get("state") == "accepted"]
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("historical regression configuration is invalid")
    environment = validate_study_environment_receipt(
        load_json(root / "inputs/study-environment.json"),
        expected_image_digest=source["image_digest"],
        allow_historical=True,
    )
    projected = {
        "root": _portable_lab_path(root),
        "name": experiment.get("name"),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "samples": len(accepted),
        "campaign_sha256": configuration.get("campaign_sha256"),
        "authoritative_bytes": len(raw)
        + sum(files[relative].stat().st_size for relative in checksums),
        "environment": environment,
    }
    if projected != value:
        raise ValueError("historical regression result projection is invalid")
    return projected


def _validate_historical_regression_summary(
    value: Any, *, source: Mapping[str, Any]
) -> dict[str, Any]:
    required = {
        "schema_version",
        "samples",
        "authoritative_bytes",
        "source",
        "results",
        "established_seven_baseline",
    }
    baseline = validate_established_seven_baseline()
    baseline["path"] = _portable_lab_path(Path(baseline["path"]))
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != 1
        or value.get("samples") != 18
        or value.get("source") != source
        or value.get("established_seven_baseline") != baseline
        or not isinstance(value.get("results"), list)
        or len(value["results"]) != 3
    ):
        raise ValueError("historical regression summary is invalid")
    results = [
        _validate_historical_result_projection(record, source=source)
        for record in value["results"]
    ]
    if (
        sum(record["samples"] for record in results) != 18
        or sum(record["authoritative_bytes"] for record in results)
        != value["authoritative_bytes"]
        or len({record["name"] for record in results}) != 3
    ):
        raise ValueError("historical regression summary totals are invalid")
    return dict(value)


def create_code_gate_receipt(
    destination: Path,
    *,
    regression_result_roots: Sequence[Path],
    cohort_version: int = 1,
) -> Path:
    """Run the Lab gates and bind them to build-stage Rust gates and regression18."""

    version = _cohort_version(cohort_version)
    source = source_metadata()
    _validate_clean_source(source, label="study code gate")
    rust = validate_rust_code_gate()
    regression = validate_regression_results(regression_result_roots)
    established = validate_established_seven_baseline()
    if regression["source"] != source or rust["source"] != source:
        raise ValueError("code-gate, regression, and collection image source differ")
    selected_build = validate_build_execution_receipt(
        build_execution_receipt_path(version),
        expected_collection_image=source["image_digest"],
        expected_cohort_version=version,
    )
    build_binding = {"path": selected_build["path"], "sha256": selected_build["sha256"]}
    expected_build_identity = _current_build_execution_identity(selected_build)
    if (
        _one_build_execution_identity([record["environment"] for record in regression["results"]])
        != expected_build_identity
    ):
        raise ValueError("code-gate regression did not use the selected cohort build")
    commands = _run_lab_code_gate_commands()
    value = {
        "schema_version": 2,
        "artifact_type": CODE_GATE_ARTIFACT_TYPE,
        "cohort_version": version,
        "study_plan": _file_binding(STUDY_PLAN),
        "build_execution_receipt": build_binding,
        "source": source,
        "rust_code_gate": rust,
        "lab_commands": commands,
        "live_regression": regression,
        "established_seven_baseline": established,
        "passed": True,
    }
    output = _create_only_json(destination, value)
    validate_code_gate_receipt(
        output,
        regression_result_roots=regression_result_roots,
        expected_cohort_version=version,
        deep=False,
    )
    return output


def validate_code_gate_receipt(
    path: Path,
    *,
    regression_result_roots: Sequence[Path] = (),
    expected_cohort_version: int | None = None,
    deep: bool = True,
    _expected_collection_source: Mapping[str, Any] | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Verify recorded execution and its bound evidence without running tests.

    ``deep`` remains accepted for caller compatibility. Both values validate
    the complete receipt, command outputs, source/build bindings, Rust gate and
    regression evidence under the selected current or historical policy. A
    fresh test execution belongs to ``create_code_gate_receipt``; verification
    attests the recorded execution, not the current ambient test environment.
    """

    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    historical = isinstance(value, Mapping) and value.get("schema_version") == 1
    if historical and not allow_historical:
        raise ValueError("current code-gate admission requires schema 2")
    if historical and allow_historical and _expected_collection_source is None:
        collection_source = dict(value.get("source", {}))
        _validate_clean_source(
            collection_source,
            label="historical study code-gate collection image",
        )
    else:
        collection_source = _expected_clean_collection_source(
            _expected_collection_source,
            label="study code-gate collection image",
        )
    required = {
        "schema_version",
        "artifact_type",
        "cohort_version",
        "study_plan",
        "build_execution_receipt",
        "source",
        "rust_code_gate",
        "lab_commands",
        "live_regression",
        "established_seven_baseline",
        "passed",
    }
    study_plan = value.get("study_plan") if isinstance(value, Mapping) else None
    historical_study_plan = (
        isinstance(study_plan, Mapping)
        and set(study_plan) == {"path", "sha256"}
        and study_plan.get("path") == "/lab/config/buflo-study/v1/study.json"
        and isinstance(study_plan.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", study_plan["sha256"]) is not None
    )
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") not in {1, 2}
        or value.get("artifact_type") != CODE_GATE_ARTIFACT_TYPE
        or (
            value.get("study_plan") != _file_binding(STUDY_PLAN)
            and not (historical and allow_historical and historical_study_plan)
        )
        or value.get("source") != collection_source
        or value.get("passed") is not True
    ):
        raise ValueError("study code-gate receipt identity or source is invalid")
    historical = value["schema_version"] == 1
    if historical and not allow_historical:
        raise ValueError("current code-gate admission requires schema 2")
    stored_version = _cohort_version(value["cohort_version"])
    if expected_cohort_version is not None and stored_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("study code-gate cohort version differs from the request")
    selected_build = validate_build_execution_receipt(
        build_execution_receipt_path(stored_version),
        expected_collection_image=value["source"]["image_digest"],
        expected_cohort_version=stored_version,
        allow_historical=historical,
    )
    selected_build_binding = {
        "path": selected_build["path"],
        "sha256": selected_build["sha256"],
    }
    expected_recorded_build_binding = (
        {
            "path": _portable_lab_path(Path(selected_build["path"])),
            "sha256": selected_build["sha256"],
        }
        if historical
        else selected_build_binding
    )
    if value["build_execution_receipt"] != expected_recorded_build_binding:
        raise ValueError("study code gate does not bind the selected cohort build")
    if selected_build["source"] != collection_source:
        raise ValueError("study code gate differs from the selected cohort build source")
    _validate_clean_source(value["source"], label="study code gate")
    rust = (
        _validate_historical_rust_code_gate_summary(
            value.get("rust_code_gate"), source=collection_source
        )
        if historical
        else validate_rust_code_gate(
            _expected_collection_source=collection_source,
        )
    )
    if value.get("rust_code_gate") != rust:
        raise ValueError("study code gate does not bind the current Rust build gate")
    commands = value.get("lab_commands")
    if not isinstance(commands, list) or len(commands) != len(_LAB_CODE_GATE_COMMANDS):
        raise ValueError("study code-gate Lab command inventory is invalid")
    for record, (gate, template) in zip(commands, _LAB_CODE_GATE_COMMANDS, strict=True):
        expected_argv = [
            (
                "/opt/qcsd-venv/bin/python"
                if historical
                else os.fspath(Path(os.sys.executable))
            )
            if item == "python"
            else item
            for item in template
        ]
        output = record.get("stdout") if isinstance(record, Mapping) else None
        if (
            not isinstance(record, Mapping)
            or set(record)
            != {
                "gate",
                "argv",
                "cwd",
                "exit_code",
                "stdout_bytes",
                "stdout_sha256",
                "stdout",
            }
            or record.get("gate") != gate
            or record.get("argv") != expected_argv
            or record.get("cwd") != ("/lab" if historical else str(LAB_ROOT))
            or record.get("exit_code") != 0
            or not isinstance(output, str)
            or record.get("stdout_bytes") != len(output.encode("utf-8"))
            or record.get("stdout_sha256") != hashlib.sha256(output.encode("utf-8")).hexdigest()
        ):
            raise ValueError(f"study code-gate command receipt is invalid: {gate}")
    regression = value.get("live_regression")
    if historical:
        expected_regression = _validate_historical_regression_summary(
            regression, source=collection_source
        )
    elif not regression_result_roots:
        results = regression.get("results") if isinstance(regression, Mapping) else None
        if not isinstance(results, list):
            raise ValueError("study code-gate regression binding is invalid")
        regression_result_roots = tuple(
            (
                _resolve_portable_lab_path(item["root"], label="historical regression result")
                if historical
                else Path(item["root"])
            )
            for item in results
            if isinstance(item, Mapping) and isinstance(item.get("root"), str)
        )
    if not historical:
        expected_regression = validate_regression_results(
            regression_result_roots,
            _expected_collection_source=collection_source,
        )
    if regression != expected_regression or expected_regression["source"] != value["source"]:
        raise ValueError("study code-gate regression18 evidence is invalid")
    expected_build_identity = (
        {
            "cohort_version": stored_version,
            "sha256": selected_build["sha256"],
            "collection_image": selected_build["collection_image"],
            "started_at": selected_build["started_at"],
            "finished_at": selected_build["finished_at"],
        }
        if historical
        else _current_build_execution_identity(selected_build)
    )
    if (
        _one_build_execution_identity(
            [record["environment"] for record in expected_regression["results"]],
            allow_historical=historical,
        )
        != expected_build_identity
    ):
        raise ValueError("study code-gate regression build differs from the selected cohort")
    expected_baseline = validate_established_seven_baseline()
    if historical:
        expected_baseline["path"] = _portable_lab_path(Path(expected_baseline["path"]))
    if value.get("established_seven_baseline") != expected_baseline:
        raise ValueError("study code gate does not bind the pre-change seven-mode oracle")
    return {"path": binding["path"], "sha256": binding["sha256"], **value}


_MANDATORY_COMPARISON_DIFFERENCE_IDS = frozenset(
    {
        "transport-and-observation-layer",
        "endpoint-cooperation-and-peer-datagram-unavailability",
        "closed-world-dataset-and-classifier-protocol",
    }
)
_MANDATORY_CSBUFLO_COMPARISON_DIFFERENCE_IDS = frozenset(
    {
        (
            "csbuflo-author-total-transmitted-vs-live-fresh-application-stream-"
            "byte-adaptation-counter"
        ),
        "csbuflo-paper-source-and-client-only-early-termination-translation",
    }
)
_MANDATORY_BUFLO_COMPARISON_DIFFERENCE_IDS = frozenset(
    {"buflo-terminal-subcell-client-local-cancellation"}
)


def _comparison_required_difference_ids(
    qcsd_rows: Sequence[Mapping[str, Any]],
) -> set[str]:
    """Derive the review inventory from the already-validated evaluator rows."""

    declared: set[str] = set()
    defenses: set[str] = set()
    for row in qcsd_rows:
        defense = row.get("defense")
        differences = row.get("known_expected_differences")
        if not isinstance(defense, str) or not isinstance(differences, list):
            raise ValueError("evaluation comparison difference inventory is invalid")
        defenses.add(defense)
        for difference in differences:
            identifier = difference.get("difference") if isinstance(difference, Mapping) else None
            if not isinstance(identifier, str) or not identifier:
                raise ValueError("evaluation comparison difference inventory is invalid")
            declared.add(identifier)
    mandatory = set(_MANDATORY_COMPARISON_DIFFERENCE_IDS)
    if "buflo" in defenses:
        mandatory.update(_MANDATORY_BUFLO_COMPARISON_DIFFERENCE_IDS)
    if "cs-buflo" in defenses:
        mandatory.update(_MANDATORY_CSBUFLO_COMPARISON_DIFFERENCE_IDS)
    if not mandatory <= declared:
        raise ValueError("evaluation comparison rows omit a mandatory difference")
    return mandatory | declared


_COMPARISON_EXPLANATION_CONTEXT_TERMS = frozenset(
    {
        "client-only",
        "dataset",
        "endpoint",
        "ethernet",
        "header",
        "observation",
        "padding",
        "protocol",
        "qcsd",
        "quic",
        "tcp",
        "transport",
    }
)


def _substantive_comparison_explanation(value: Any, *, identifiers: Sequence[str]) -> bool:
    if not isinstance(value, str):
        return False
    explanation = " ".join(value.split())
    lowered = explanation.casefold()
    words = re.findall(r"[a-z0-9][a-z0-9+_.-]*", lowered)
    return bool(
        len(explanation) >= 80
        and len(words) >= 12
        and all(identifier.casefold() in lowered for identifier in identifiers)
        and any(term in lowered for term in _COMPARISON_EXPLANATION_CONTEXT_TERMS)
    )


def _comparison_required_anchor_metrics(
    qcsd_rows: Sequence[Mapping[str, Any]],
    historical_rows: Sequence[Mapping[str, Any]],
    inventory: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str, str], dict[str, str]]:
    """Bind every published outcome metric to its relevant QCSD defense row."""

    qcsd_by_defense = {
        str(row["defense"]): _canonical_digest(row)
        for row in qcsd_rows
        if isinstance(row, Mapping) and isinstance(row.get("defense"), str)
    }
    historical_by_anchor = {
        str(row["anchor_id"]): _canonical_digest(row)
        for row in historical_rows
        if isinstance(row, Mapping) and isinstance(row.get("anchor_id"), str)
    }
    expected: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in inventory:
        if not isinstance(item, Mapping):
            raise ValueError("comparison anchor/metric inventory is invalid")
        anchor_id = item.get("anchor_id")
        row_digest = item.get("historical_row_sha256")
        metric_paths = item.get("metric_paths")
        defense = (
            "buflo"
            if isinstance(anchor_id, str) and anchor_id.startswith("buflo-")
            else (
                "cs-buflo"
                if isinstance(anchor_id, str) and anchor_id.startswith("csbuflo-")
                else None
            )
        )
        if (
            defense not in qcsd_by_defense
            or not isinstance(anchor_id, str)
            or historical_by_anchor.get(anchor_id) != row_digest
            or not isinstance(metric_paths, list)
            or not metric_paths
            or any(not isinstance(metric, str) or not metric for metric in metric_paths)
            or len(metric_paths) != len(set(metric_paths))
        ):
            raise ValueError("comparison anchor/metric inventory is invalid")
        for metric in metric_paths:
            key = (defense, anchor_id, metric)
            if key in expected:
                raise ValueError("comparison anchor/metric inventory is not unique")
            expected[key] = {
                "evaluation_row_sha256": qcsd_by_defense[defense],
                "historical_row_sha256": str(row_digest),
            }
    if not expected:
        raise ValueError("comparison anchor/metric inventory is empty")
    return expected


def validate_comparison_review(
    path: Path,
    *,
    evaluation_receipt: Path,
    handoff: Path,
    formal: bool = True,
    dlsvm_available_wall_seconds: float | None = None,
) -> dict[str, Any]:
    """Validate a human-authored review without mutating evaluation evidence."""

    from .buflo_evaluation import validate_evaluation_receipt
    from .buflo_handoff import validate_study_handoff

    handoff_root = validate_study_handoff(handoff, formal=formal, deep=True)
    evaluation = validate_evaluation_receipt(
        evaluation_receipt,
        handoff_root=handoff_root,
        formal=formal,
        deep=True,
        dlsvm_available_wall_seconds=dlsvm_available_wall_seconds,
    )
    return _validate_comparison_review_value(
        path,
        evaluation_receipt=evaluation_receipt,
        handoff_root=handoff_root,
        evaluation=evaluation,
        formal=formal,
    )


def _validate_comparison_review_value(
    path: Path,
    *,
    evaluation_receipt: Path,
    handoff_root: Path,
    evaluation: Mapping[str, Any],
    formal: bool,
) -> dict[str, Any]:
    """Validate review contents against dependencies already verified by the caller."""

    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    required = {
        "schema_version",
        "artifact_type",
        "formal",
        "implementation_scope",
        "paper_equivalent",
        "evaluation",
        "handoff",
        "reviewer",
        "reviewed_at",
        "rows",
        "required_differences",
        "passed",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != 2
        or value.get("artifact_type") != COMPARISON_REVIEW_ARTIFACT_TYPE
        or value.get("formal") is not formal
        or value.get("implementation_scope") != "client_only_quic"
        or value.get("paper_equivalent") is not False
        or value.get("evaluation") != _file_binding(evaluation_receipt)
        or value.get("passed") is not True
        or not isinstance(value.get("reviewer"), str)
        or not value["reviewer"].strip()
        or not isinstance(value.get("reviewed_at"), str)
    ):
        raise ValueError("comparison review identity or provenance is invalid")
    try:
        reviewed_at = datetime.fromisoformat(value["reviewed_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("comparison review timestamp is invalid") from error
    if reviewed_at.tzinfo is None:
        raise ValueError("comparison review timestamp must include a timezone")
    expected_handoff = {
        "root": str(handoff_root),
        "sha256sums_sha256": sha256_file(handoff_root / "SHA256SUMS"),
        "dataset_sha256": sha256_file(handoff_root / "dataset.json"),
        "samples_sha256": sha256_file(handoff_root / "samples.jsonl"),
    }
    if value.get("handoff") != expected_handoff:
        raise ValueError("comparison review handoff binding is invalid")
    qcsd_rows = evaluation.get("original_study_comparison", {}).get("qcsd_rows")
    historical_rows = evaluation.get("original_study_comparison", {}).get("historical_rows")
    anchor_inventory = evaluation.get("original_study_comparison", {}).get(
        "anchor_metric_inventory"
    )
    reviews = value.get("rows")
    if (
        not isinstance(qcsd_rows, list)
        or not isinstance(historical_rows, list)
        or not isinstance(anchor_inventory, list)
        or not isinstance(reviews, list)
    ):
        raise ValueError("comparison review rows are invalid")
    expected = _comparison_required_anchor_metrics(qcsd_rows, historical_rows, anchor_inventory)
    observed: set[tuple[str, str, str]] = set()
    for row in reviews:
        if (
            not isinstance(row, Mapping)
            or set(row)
            != {
                "defense",
                "evaluation_row_sha256",
                "anchor_id",
                "historical_row_sha256",
                "metric",
                "classification",
                "explanation",
            }
            or row.get("classification") not in {"expected", "resolved"}
        ):
            raise ValueError("comparison review contains an invalid row")
        key = (str(row.get("defense")), str(row.get("anchor_id")), str(row.get("metric")))
        row_binding = expected.get(key)
        if (
            key in observed
            or row_binding is None
            or row.get("evaluation_row_sha256") != row_binding["evaluation_row_sha256"]
            or row.get("historical_row_sha256") != row_binding["historical_row_sha256"]
            or not _substantive_comparison_explanation(
                row.get("explanation"), identifiers=(key[1], key[2])
            )
        ):
            raise ValueError("comparison review row inventory or digest is invalid")
        observed.add(key)
    if observed != set(expected):
        raise ValueError("comparison review does not reconcile every anchor/metric pair")
    differences = value.get("required_differences")
    required_difference_ids = _comparison_required_difference_ids(qcsd_rows)
    if not isinstance(differences, list) or len(differences) != len(required_difference_ids):
        raise ValueError("comparison review required-difference inventory is incomplete")
    observed_difference_ids: set[str] = set()
    for row in differences:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"difference", "classification", "explanation"}
            or row.get("classification") not in {"expected", "resolved"}
            or not isinstance(row.get("difference"), str)
            or not _substantive_comparison_explanation(
                row.get("explanation"), identifiers=(str(row.get("difference")),)
            )
        ):
            raise ValueError("comparison review required difference is invalid")
        observed_difference_ids.add(str(row["difference"]))
    if observed_difference_ids != required_difference_ids:
        raise ValueError("comparison review required-difference inventory is incomplete")
    return {
        "path": binding["path"],
        "sha256": binding["sha256"],
        "reviewer": value["reviewer"],
        "reviewed_at": value["reviewed_at"],
        "rows": len(reviews),
        "required_differences": sorted(required_difference_ids),
        "passed": True,
    }


def validate_controlled_results(
    result_roots: Sequence[Path],
    *,
    explanation_receipt: Path | None = None,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Deep-verify the exact generated 160-cell controlled qualification matrix."""

    return _validate_local_stage_results(
        "controlled",
        result_roots,
        explanation_receipt=explanation_receipt,
        _expected_collection_source=_expected_collection_source,
    )


def validate_regression_results(
    result_roots: Sequence[Path],
    *,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify the 18-cell matrix and its excluded all-nine two-origin proof."""

    return _validate_local_stage_results(
        "regression",
        result_roots,
        _expected_collection_source=_expected_collection_source,
    )


def _validate_canonical_reference_receipt(path: Path) -> dict[str, Any]:
    """Validate the deterministic inner conformance receipt byte-for-byte."""

    canonical_receipt_sha256 = sha256_file(CONFORMANCE_RECEIPT)
    if canonical_receipt_sha256 != CONFORMANCE_RECEIPT_SHA256:
        raise ValueError("immutable checked-in reference oracle SHA-256 is invalid")
    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"reference gate receipt is not a regular file: {path}")
    value = load_json(path)
    required = {
        "artifact_type",
        "buflo_author_conformance",
        "clean_room",
        "csbuflo_archive_conformance",
        "csbuflo_author_conformance",
        "csbuflo_estimator_contract",
        "csbuflo_paper_internal_discrepancies",
        "external_sources",
        "passed",
        "reference_documents",
        "schema_version",
    }
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-buflo-csbuflo-conformance-receipt"
        or value.get("clean_room") is not True
        or value.get("passed") is not True
    ):
        raise ValueError("reference gate receipt identity/pass state is invalid")

    buflo = value["buflo_author_conformance"]
    profiles = buflo.get("profiles") if isinstance(buflo, Mapping) else None
    if (
        not isinstance(profiles, list)
        or len(profiles) != 8
        or len({row.get("profile") for row in profiles if isinstance(row, Mapping)}) != 8
        or any(
            not isinstance(row, Mapping)
            or row.get("source_match") is not True
            or not isinstance(row.get("event_count"), int)
            or isinstance(row.get("event_count"), bool)
            or row["event_count"] <= 0
            for row in profiles
        )
    ):
        raise ValueError("reference gate did not pass all eight BuFLO author profiles")

    author = value["csbuflo_author_conformance"]
    extraction = author.get("source_extraction") if isinstance(author, Mapping) else None
    golden = author.get("golden_vectors") if isinstance(author, Mapping) else None
    from .buflo_reference import csbuflo_author_golden_projection

    expected_golden = csbuflo_author_golden_projection()
    if (
        not isinstance(author, Mapping)
        or author.get("source_match") is not True
        or author.get("independent_oracle_match") is not True
        or not isinstance(extraction, Mapping)
        or extraction.get("active_padding_profile") != "CPSP-payload-at-both-endpoints"
        or extraction.get("payload_padding_source_executed") is not True
        or extraction.get("total_padding_source_expression_executed") is not True
        or extraction.get("total_padding_active_in_pinned_runtime") is not False
        or extraction.get("jitter_source_function_executed") is not True
        or extraction.get("termination_predicates_and_state_actions_executed") is not True
        or extraction.get("server_padding_done_reset_executed") is not True
        or extraction.get("padding_done_flag_author_object_executed") is not True
        or extraction.get("quiet_function_author_object_executed") is not True
        or extraction.get("early_termination_source_state_machine_executed") is not True
        or extraction.get("early_termination_quiet_comparison") != "inclusive-elapsed-us>=2000000"
        or extraction.get("paper_algorithm4_power_crossing_validation")
        != "independent-oracle-only-no-distinct-exported-author-helper"
        or extraction.get("padding_done_active_consumer_count") != 0
        or extraction.get("padding_done_dispatch_paths_verified") != ["SSH1", "SSH2"]
        or extraction.get("full_network_loop_executed") is not False
        or extraction.get("full_network_loop_status")
        != "not-executed-requires-historical-bilateral-openssh-runtime-and-obsolete-crypto-abi"
        or not isinstance(golden, Mapping)
        or golden != expected_golden
    ):
        raise ValueError("reference gate did not pass the CS-BuFLO author harness")
    segments = extraction.get("segment_sha256")
    if (
        not isinstance(segments, Mapping)
        or set(segments) != CSBUFLO_AUTHOR_SOURCE_SEGMENTS
        or dict(segments) != CSBUFLO_AUTHOR_SOURCE_SEGMENT_SHA256
        or any(
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in segments.values()
        )
    ):
        raise ValueError("reference gate CS-BuFLO source-slice inventory is invalid")
    segment_projection = json.dumps(dict(segments), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if hashlib.sha256(segment_projection).hexdigest() != author.get(
        "source_extraction_input_sha256"
    ):
        raise ValueError("reference gate CS-BuFLO source-slice aggregate is invalid")
    for digest_key in (
        "author_object_sha256",
        "author_source_slice_object_sha256",
        "harness_sha256",
        "source_slice_translation_sha256",
    ):
        digest = author.get(digest_key)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("reference gate CS-BuFLO executable binding is invalid")
    expected_rate_discrepancy = {
        "classification": "known-internal-paper-prose-vs-algorithm-conflict",
        "paper_algorithm_location": "Algorithm-2-lines-382-and-395-396",
        "paper_algorithm_rule": "2**floor(log2(median-eligible-interval))",
        "paper_prose_location": "WPES-2014-lines-450-455",
        "paper_prose_rule": "round-up-rho-to-a-power-of-two",
        "resolution_basis": "algorithm-pseudocode-and-formula-control-the-independent-oracle",
        "resolved_rule": "2**floor(log2(upper-integer-median-interval))",
    }
    if value["csbuflo_paper_internal_discrepancies"] != [expected_rate_discrepancy]:
        raise ValueError("reference gate CS-BuFLO paper-internal discrepancy is invalid")
    estimator = value["csbuflo_estimator_contract"]
    if estimator != {
        "adaptation_counter": "per-direction-actually-transmitted-real-plus-junk-bytes",
        "direction_windows": ["outgoing", "incoming"],
        "first_boundary_bytes": 16_384,
        "max_samples_per_direction": 1_000,
        "next_boundary_rule": "double-after-each-adaptation",
        "rate_quantization": "2**floor(log2(upper-integer-median-interval))",
        "rate_quantization_resolution": "paper-Algorithm-2-floor-formula",
    }:
        raise ValueError("reference gate CS-BuFLO estimator contract is invalid")
    archive = value["csbuflo_archive_conformance"]
    expected_archive = {
        "total_records": 4_000,
        "included_records": 3_824,
        "zero_baseline_records": 176,
        "defended_bytes": 7_592_598_380,
        "baseline_bytes": 3_326_013_453,
        "excluded_defended_bytes": 18_656_832,
    }
    if (
        not isinstance(archive, Mapping)
        or any(archive.get(key) != expected for key, expected in expected_archive.items())
        or not isinstance(archive.get("bandwidth_ratio"), (int, float))
        or isinstance(archive.get("bandwidth_ratio"), bool)
        or not math.isclose(
            float(archive["bandwidth_ratio"]),
            2.282792444255336,
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        or not math.isclose(
            float(archive["bandwidth_ratio"]),
            archive["defended_bytes"] / archive["baseline_bytes"],
            rel_tol=0.0,
            abs_tol=1e-15,
        )
    ):
        raise ValueError("reference gate CS-BuFLO archive conformance is invalid")

    sources = value["external_sources"]
    if not isinstance(sources, list) or any(not isinstance(row, Mapping) for row in sources):
        raise ValueError("reference gate external source bindings are invalid")
    source_ids = [row.get("source_id") for row in sources]
    if len(source_ids) != len(set(source_ids)) or set(source_ids) != REQUIRED_REFERENCE_SOURCES:
        raise ValueError("reference gate external source inventory is incomplete")
    for row in sources:
        digest = row.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(row.get("url"), str)
            or not row["url"]
        ):
            raise ValueError("reference gate external source binding is malformed")

    validated_references = validate_references()
    expected_source_bindings: dict[str, dict[str, str]] = {}
    for reference_path in REFERENCE_FILES:
        receipt = load_json(reference_path.with_suffix(".receipt.json"))
        receipt_sources = receipt.get("sources") if isinstance(receipt, Mapping) else None
        if not isinstance(receipt_sources, list) or any(
            not isinstance(row, Mapping) for row in receipt_sources
        ):
            raise ValueError("immutable checked-in primary reference sources are invalid")
        for row in receipt_sources:
            source_id = row.get("source_id")
            if not isinstance(source_id, str) or source_id in expected_source_bindings:
                raise ValueError("immutable checked-in primary reference source IDs are invalid")
            expected_source_bindings[source_id] = {
                key: row[key] for key in ("git_commit", "sha256", "source_id", "url") if key in row
            }
    observed_source_bindings = {
        row["source_id"]: {
            key: row[key] for key in ("git_commit", "sha256", "source_id", "url") if key in row
        }
        for row in sources
    }
    if observed_source_bindings != expected_source_bindings:
        raise ValueError(
            "reference gate source bindings differ from immutable checked-in oracle receipts"
        )

    expected_documents = {
        record["reference_id"]: (record["sha256"], record["receipt_sha256"])
        for record in validated_references
        if "reference_id" in record
    }
    documents = value["reference_documents"]
    if not isinstance(documents, list) or any(not isinstance(row, Mapping) for row in documents):
        raise ValueError("reference gate document bindings are invalid")
    observed_documents = {
        row.get("reference_id"): (
            row.get("reference_sha256"),
            row.get("receipt_sha256"),
        )
        for row in documents
    }
    if observed_documents != expected_documents or len(documents) != len(expected_documents):
        raise ValueError("reference gate document bindings do not match checked-in references")
    canonical = load_json(CONFORMANCE_RECEIPT)
    if value != canonical:
        raise ValueError("reference gate receipt differs from the immutable checked-in oracle")
    receipt_sha256 = sha256_file(path)
    if receipt_sha256 != canonical_receipt_sha256:
        raise ValueError(
            "reference gate receipt SHA-256 differs from the immutable checked-in oracle"
        )
    return {
        "path": str(path),
        "sha256": receipt_sha256,
        "profiles_checked": 8,
        "archive": dict(expected_archive),
        "bandwidth_ratio": archive["bandwidth_ratio"],
        "external_sources": sorted(source_ids),
    }


def _reference_execution_log() -> list[dict[str, str]]:
    return [
        {"step": "validate-pinned-input-inventory", "status": "passed"},
        {"step": "execute-buflo-eight-profile-author-oracle", "status": "passed"},
        {"step": "execute-csbuflo-author-source-slices", "status": "passed"},
        {"step": "audit-csbuflo-4000-record-archive", "status": "passed"},
        {"step": "compare-canonical-conformance-receipt", "status": "passed"},
    ]


def _reference_input_inventory() -> list[dict[str, str]]:
    canonical = load_json(CONFORMANCE_RECEIPT)
    sources = canonical.get("external_sources") if isinstance(canonical, Mapping) else None
    if not isinstance(sources, list) or any(not isinstance(row, Mapping) for row in sources):
        raise ValueError("immutable reference input inventory is invalid")
    by_id = {str(row.get("source_id")): row for row in sources}
    if set(by_id) != set(REFERENCE_INPUT_RELATIVE_PATHS):
        raise ValueError("immutable reference input inventory is incomplete")
    return [
        {
            "source_id": source_id,
            "relative_path": REFERENCE_INPUT_RELATIVE_PATHS[source_id],
            "sha256": str(by_id[source_id]["sha256"]),
        }
        for source_id in sorted(by_id)
    ]


def _reference_runtime_isolation() -> dict[str, Any]:
    """Prove the reference process has only loopback and read-only author inputs."""

    if (
        os.environ.get("QCSD_REFERENCE_ISOLATED") != "1"
        or os.environ.get("QCSD_REFERENCE_NETWORK_MODE") != "none"
    ):
        raise ValueError("reference execution lacks the isolated wrapper markers")
    interfaces_root = Path("/sys/class/net")
    interfaces = sorted(path.name for path in interfaces_root.iterdir())
    if interfaces != ["lo"]:
        raise ValueError("reference execution network namespace is not loopback-only")

    mount_options: dict[str, set[str]] = {}
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError("reference execution cannot inspect mount isolation") from error
    for line in lines:
        fields = line.split()
        if len(fields) >= 6 and fields[4] in {"/reference-input", "/reference-output"}:
            mount_options[fields[4]] = set(fields[5].split(","))
    if "ro" not in mount_options.get("/reference-input", set()):
        raise ValueError("reference author input mount is not read-only")
    if "rw" not in mount_options.get("/reference-output", set()):
        raise ValueError("reference receipt output mount is not writable")
    return {
        "environment_marker": "QCSD_REFERENCE_ISOLATED=1",
        "docker_network_mode": "none",
        "observed_interfaces": interfaces,
        "reference_inputs_read_only": True,
        "output_mount_writable": True,
        "output_create_only": True,
        "ordinary_collection_contains_author_code": False,
    }


def _reference_execution_value(
    *,
    source: Mapping[str, Any],
    build_execution: Mapping[str, Any],
    isolation: Mapping[str, Any],
    execution_id: str,
    started_at: str,
    finished_at: str,
    duration_seconds: float,
) -> dict[str, Any]:
    canonical = _validate_canonical_reference_receipt(CONFORMANCE_RECEIPT)
    log = _reference_execution_log()
    current_build = "completion" in build_execution
    value: dict[str, Any] = {
        "schema_version": 2 if current_build else 1,
        "artifact_type": REFERENCE_EXECUTION_ARTIFACT_TYPE,
        "execution_id": execution_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration_seconds,
        "reference_image": {"id": source.get("image_digest"), "source": dict(source)},
        "build_execution": dict(build_execution),
        "isolation": dict(isolation),
        "conformance_receipt": {
            "artifact_type": "qcsd-buflo-csbuflo-conformance-receipt",
            "sha256": canonical["sha256"],
            "profiles_checked": canonical["profiles_checked"],
            "archive": canonical["archive"],
            "passed": True,
        },
        "external_inputs": _reference_input_inventory(),
        "execution_log": log,
        "execution_log_sha256": _canonical_digest(log),
    }
    value["payload_sha256"] = _canonical_digest(value)
    return value


def validate_reference_gate_receipt(
    path: Path,
    *,
    expected_cohort_version: int | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Validate a fresh outer execution receipt, never the static oracle itself."""

    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    expected_keys = {
        "schema_version",
        "artifact_type",
        "execution_id",
        "started_at",
        "finished_at",
        "duration_seconds",
        "reference_image",
        "build_execution",
        "isolation",
        "conformance_receipt",
        "external_inputs",
        "execution_log",
        "execution_log_sha256",
        "payload_sha256",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_keys
        or value.get("schema_version") not in {1, 2}
        or value.get("artifact_type") != REFERENCE_EXECUTION_ARTIFACT_TYPE
        or not isinstance(value.get("execution_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", value["execution_id"]) is None
    ):
        raise ValueError("reference execution receipt identity is invalid")
    if value["schema_version"] != 2 and not allow_historical:
        raise ValueError(
            "current reference admission requires schema 2 and build completion"
        )
    payload = dict(value)
    payload_sha256 = payload.pop("payload_sha256")
    if payload_sha256 != _canonical_digest(payload):
        raise ValueError("reference execution receipt payload hash is invalid")
    try:
        started = datetime.fromisoformat(str(value["started_at"]).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(value["finished_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("reference execution timestamps are invalid") from error
    duration = value["duration_seconds"]
    wall_seconds = (finished - started).total_seconds()
    if (
        started.tzinfo is None
        or finished.tzinfo is None
        or finished < started
        or not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or duration < 0
        or abs(float(duration) - wall_seconds) > 1.0
    ):
        raise ValueError("reference execution duration/timestamps are invalid")
    image = value["reference_image"]
    if not isinstance(image, Mapping) or set(image) != {"id", "source"}:
        raise ValueError("reference execution image binding is invalid")
    _validate_clean_source(image["source"], label="reference execution")
    if image["id"] != image["source"]["image_digest"]:
        raise ValueError("reference execution image ID differs from source metadata")
    build_binding = value["build_execution"]
    historical_build_keys = {"sha256", "receipt"}
    current_build_keys = historical_build_keys | {
        "completion_path",
        "completion_sha256",
        "completion_payload_sha256",
        "completion",
    }
    if not isinstance(build_binding, Mapping) or set(build_binding) != (
        current_build_keys if value["schema_version"] == 2 else historical_build_keys
    ):
        raise ValueError("reference execution build binding is invalid")
    build_receipt = build_binding["receipt"]
    encoded_build = (json.dumps(build_receipt, indent=2, sort_keys=True) + "\n").encode()
    if build_binding["sha256"] != hashlib.sha256(encoded_build).hexdigest():
        raise ValueError("reference execution build receipt hash is invalid")
    build = _validate_build_execution_value(
        build_receipt,
        expected_cohort_version=expected_cohort_version,
        allow_historical=value["schema_version"] == 1 and allow_historical,
    )
    completed_build: dict[str, Any] | None = None
    if value["schema_version"] == 2:
        version = build["cohort_version"]
        expected_completion_path = (
            f"/lab/artifacts/buflo-study/build-completion-v{version}.json"
        )
        completion_value = build_binding["completion"]
        completion_raw = _canonical_finite_json_bytes(
            completion_value, label="reference build completion", newline=True
        )
        completion_receipt = completion_value.get("receipt") if isinstance(
            completion_value, Mapping
        ) else None
        if (
            build.get("schema_version") != 5
            or build_binding.get("completion_path") != expected_completion_path
            or build_binding.get("completion_sha256")
            != hashlib.sha256(completion_raw).hexdigest()
            or not isinstance(completion_receipt, Mapping)
        ):
            raise ValueError("reference execution build completion binding is invalid")
        completed_build = validate_build_completion_authority(
            completion_value,
            completion_path=Path(expected_completion_path),
            receipt_path=Path(
                f"/lab/artifacts/buflo-study/build-execution-v{version}.json"
            ),
            receipt_raw=encoded_build,
            receipt_value=build_receipt,
            receipt_stat=completion_receipt.get("stat"),
            expected_cohort_version=version,
        )
        if completed_build["payload_sha256"] != build_binding.get(
            "completion_payload_sha256"
        ):
            raise ValueError("reference execution build completion payload is invalid")
    if build["images"]["reference"]["id"] != image["id"]:
        raise ValueError("reference execution image differs from its no-cache build")
    build_source = dict(build["source"])
    reference_source = dict(image["source"])
    build_source.pop("image_digest")
    reference_source.pop("image_digest")
    if build_source != reference_source:
        raise ValueError("reference execution source differs from its no-cache build")
    expected_isolation = {
        "environment_marker": "QCSD_REFERENCE_ISOLATED=1",
        "docker_network_mode": "none",
        "observed_interfaces": ["lo"],
        "reference_inputs_read_only": True,
        "output_mount_writable": True,
        "output_create_only": True,
        "ordinary_collection_contains_author_code": False,
    }
    if value["isolation"] != expected_isolation:
        raise ValueError("reference execution isolation evidence is invalid")
    canonical = _validate_canonical_reference_receipt(CONFORMANCE_RECEIPT)
    expected_conformance = {
        "artifact_type": "qcsd-buflo-csbuflo-conformance-receipt",
        "sha256": canonical["sha256"],
        "profiles_checked": 8,
        "archive": canonical["archive"],
        "passed": True,
    }
    if value["conformance_receipt"] != expected_conformance:
        raise ValueError("reference execution conformance binding is invalid")
    if value["external_inputs"] != _reference_input_inventory():
        raise ValueError("reference execution author input inventory is invalid")
    log = _reference_execution_log()
    if value["execution_log"] != log or value["execution_log_sha256"] != _canonical_digest(log):
        raise ValueError("reference execution log binding is invalid")
    return {
        "path": binding["path"],
        "sha256": binding["sha256"],
        "execution_id": value["execution_id"],
        "reference_image": dict(image),
        "build_execution": {
            "cohort_version": build["cohort_version"],
            "sha256": build_binding["sha256"],
            "collection_image": build["collection_image"],
            "started_at": build["started_at"],
            "finished_at": build["finished_at"],
        },
        "profiles_checked": 8,
        "archive": canonical["archive"],
        "bandwidth_ratio": canonical["bandwidth_ratio"],
        "external_sources": canonical["external_sources"],
        "isolation": dict(value["isolation"]),
    } | (
        {
            "build_execution": {
                "cohort_version": build["cohort_version"],
                "sha256": build_binding["sha256"],
                "completion_path": build_binding["completion_path"],
                "completion_sha256": build_binding["completion_sha256"],
                "collection_image": build["collection_image"],
                "started_at": build["started_at"],
                "finished_at": build["finished_at"],
            }
        }
        if completed_build is not None
        else {}
    )


def _validate_build_execution_value(
    value: Any,
    *,
    expected_collection_image: str | None = None,
    expected_cohort_version: int | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    envelope = validate_build_execution_envelope(
        value,
        expected_cohort_version=expected_cohort_version,
        expected_probe_sha256=(
            None
            if allow_historical
            else sha256_file(LAB_ROOT / "tools/windows_docker_storage_probe.ps1")
        ),
        # A historical receipt proves the immutable bytes and source identity
        # recorded at execution time.  It must not be rebound to a later
        # checkout's Dockerfile/lockfiles merely because it is inspected from
        # that checkout.  Current admission remains ambient-bound below.
        checkout_root=None if allow_historical else LAB_ROOT,
    )
    cohort_version = _cohort_version(value["cohort_version"])
    if expected_cohort_version is not None and cohort_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("study no-cache build cohort version differs from the request")
    payload = dict(value)
    payload_sha256 = payload.pop("payload_sha256")
    if payload_sha256 != _canonical_digest(payload):
        raise ValueError("study no-cache build execution payload hash is invalid")
    try:
        started = datetime.fromisoformat(str(value["started_at"]).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(value["finished_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("study no-cache build timestamps are invalid") from error
    duration = value["duration_seconds"]
    wall_seconds = (finished - started).total_seconds()
    if (
        started.tzinfo is None
        or finished.tzinfo is None
        or finished < started
        or not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or duration <= 0
        or abs(float(duration) - wall_seconds) > 2.0
    ):
        raise ValueError("study no-cache build duration is invalid")
    docker = value["docker"]
    expected_docker_keys = {"client_version", "server_version"}
    if value["schema_version"] in {2, 3, 4, 5}:
        expected_docker_keys |= {
            "context",
            "endpoint",
            "server_name",
            "server_operating_system",
            "server_os_type",
            "server_architecture",
            "server_id",
        }
    if (
        not isinstance(docker, Mapping)
        or set(docker) != expected_docker_keys
        or any(not isinstance(docker[key], str) or not docker[key] for key in docker)
    ):
        raise ValueError("study no-cache build Docker version binding is invalid")
    images = value["images"]
    if not isinstance(images, Mapping) or set(images) != {"collection", "prepare", "reference"}:
        raise ValueError("study no-cache build image inventory is invalid")
    for target, record in images.items():
        if (
            not isinstance(record, Mapping)
            or set(record) != {"tag", "id", "repo_digests"}
            or not isinstance(record["tag"], str)
            or not record["tag"]
            or not isinstance(record["id"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", record["id"]) is None
            or not isinstance(record["repo_digests"], list)
            or any(
                not isinstance(digest, str) or re.search(r"@sha256:[0-9a-f]{64}$", digest) is None
                for digest in record["repo_digests"]
            )
        ):
            raise ValueError(f"study no-cache build {target} image binding is invalid")
        if value["schema_version"] in {2, 3, 4, 5} and record["tag"] != BUILD_IMAGE_TAGS[target]:
            raise ValueError(f"study no-cache build {target} image role tag is invalid")
    if value["schema_version"] in {2, 3, 4, 5} and len(
        {record["id"] for record in images.values()}
    ) != len(images):
        raise ValueError("study no-cache build image roles do not have distinct immutable IDs")
    collection_id = images["collection"]["id"]
    if expected_collection_image is not None and collection_id != expected_collection_image:
        raise ValueError("study no-cache build collection image differs from capture image")
    commands = value["commands"]
    if not isinstance(commands, list) or len(commands) != 3:
        raise ValueError("study no-cache build command inventory is incomplete")
    expected_targets = ("collection", "prepare", "reference")
    recorded_build_root: Path | None = None
    for target, command in zip(expected_targets, commands, strict=True):
        expected_prefix = ["docker"]
        if value["schema_version"] == 2:
            expected_prefix.extend(["--context", docker["context"]])
        elif value["schema_version"] in {3, 4, 5}:
            expected_prefix.extend(["--host", docker["endpoint"]])
        expected_prefix.extend(["build", "--pull", "--no-cache"])
        argv = command.get("argv") if isinstance(command, Mapping) else None
        iidfile_value: str | None = None
        iidfile: Path | None = None
        if (
            value["schema_version"] in {2, 3, 4, 5}
            and isinstance(argv, list)
            and len(argv) >= len(expected_prefix) + 2
            and argv[len(expected_prefix)] == "--iidfile"
            and isinstance(argv[len(expected_prefix) + 1], str)
        ):
            iidfile_value = argv[len(expected_prefix) + 1]
            iidfile = Path(iidfile_value)
            expected_prefix.extend(["--iidfile", iidfile_value])
        expected_prefix.extend(["--target", target, "--tag", images[target]["tag"], "--file"])
        path_arguments_valid = (
            isinstance(argv, list)
            and len(argv) == len(expected_prefix) + 2
            and isinstance(argv[-2], str)
            and isinstance(argv[-1], str)
        )
        dockerfile = Path(argv[-2]) if path_arguments_valid else None
        build_root = Path(argv[-1]) if path_arguments_valid else None
        if (
            not isinstance(command, Mapping)
            or set(command) != {"target", "argv", "exit_code", "image_id"}
            or command.get("target") != target
            or not isinstance(argv, list)
            or argv[:-2] != expected_prefix
            or dockerfile is None
            or build_root is None
            or not dockerfile.is_absolute()
            or not build_root.is_absolute()
            or argv[-2].startswith("//")
            or argv[-1].startswith("//")
            or str(dockerfile) != argv[-2]
            or str(build_root) != argv[-1]
            or ".." in dockerfile.parts
            or ".." in build_root.parts
            or build_root.parent == build_root
            or dockerfile.name != "Dockerfile"
            or dockerfile.parent != build_root
            or (
                value["schema_version"] in {2, 3, 4, 5}
                and (
                    iidfile is None
                    or not iidfile.is_absolute()
                    or str(iidfile) != iidfile_value
                    or str(iidfile).startswith("//")
                    or ".." in iidfile.parts
                    or iidfile.name != f"{target}.iid"
                    or iidfile.parent.parent != build_root / "artifacts" / "buflo-study"
                    or re.fullmatch(
                        rf"[.]build-iids-v{cohort_version}[.][A-Za-z0-9]{{6}}",
                        iidfile.parent.name,
                    )
                    is None
                )
            )
            or (recorded_build_root is not None and build_root != recorded_build_root)
            or command.get("exit_code") != 0
            or command.get("image_id") != images[target]["id"]
        ):
            raise ValueError("study build commands do not prove --pull --no-cache execution")
        recorded_build_root = build_root
    if value["cache_policy"] != {
        "pull": True,
        "no_cache": True,
        "scope": "Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only",
    }:
        raise ValueError("study build cache policy is invalid")
    source = value["source"]
    _validate_clean_source(source, label="study no-cache build")
    if source["image_digest"] != collection_id:
        raise ValueError("study no-cache build source does not bind the collection image")
    build = value["build_inputs"]
    if not allow_historical and (
        not isinstance(build, Mapping)
        or build.get("schema_version") != 1
        or build.get("artifact_type") != "qcsd-study-build-inputs"
        or build.get("rust_base_image") != RUST_BASE_IMAGE
        or build.get("debian_base_image") != DEBIAN_BASE_IMAGE
        or build.get("uv_lock_sha256") != sha256_file(LAB_ROOT / "uv.lock")
        or build.get("cargo_lock_sha256") != sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock")
    ):
        raise ValueError("study no-cache build inputs are invalid")
    if not allow_historical and value["dockerfile_sha256"] != sha256_file(
        LAB_ROOT / "Dockerfile"
    ):
        raise ValueError("study no-cache build Dockerfile binding is stale")
    validated = {
        "cohort_version": cohort_version,
        "collection_image": collection_id,
        "images": {target: dict(record) for target, record in images.items()},
        "source": dict(source),
        "started_at": value["started_at"],
        "finished_at": value["finished_at"],
        "passed": True,
    }
    if value["schema_version"] in {4, 5}:
        validated["schema_version"] = value["schema_version"]
        validated["buildx"] = envelope["buildx"]
    if value["schema_version"] == 5:
        validated["cohort_allocation"] = envelope["cohort_allocation"]
        validated["cohort_claim"] = envelope["cohort_claim"]
        validated["cohort_claim_chain"] = envelope["cohort_claim_chain"]
        validated["cohort_authority_reproofs"] = envelope[
            "cohort_authority_reproofs"
        ]
    return validated


def validate_build_execution_receipt(
    path: Path,
    *,
    expected_collection_image: str | None = None,
    expected_cohort_version: int | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    resolved, raw, value = load_stable_build_execution(path)
    if (
        not isinstance(value, Mapping)
        or value.get("schema_version") not in {1, 2, 3, 4, 5}
    ):
        raise ValueError("study no-cache build execution schema is invalid")
    if value["schema_version"] != 5 and not allow_historical:
        raise ValueError("current study build admission requires schema 5 and its completion")
    binding = {
        "path": str(resolved),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    validated = _validate_build_execution_value(
        value,
        expected_collection_image=expected_collection_image,
        expected_cohort_version=expected_cohort_version,
        allow_historical=allow_historical,
    )
    expected_path = build_execution_receipt_path(validated["cohort_version"]).resolve()
    if Path(binding["path"]) != expected_path:
        raise ValueError("study no-cache build receipt path does not match its cohort version")
    if validated.get("schema_version") == 5:
        rebound_path, rebound_raw, rebound_value, rebound_stat = (
            load_stable_build_execution_with_stat(path)
        )
        if rebound_path != resolved or rebound_raw != raw or rebound_value != value:
            raise ValueError("study build receipt changed before completion validation")
        completion_expected = build_completion_path(
            rebound_path, validated["cohort_version"]
        )
        completion_path, completion_raw, completion_value = load_stable_build_completion(
            completion_expected
        )
        completion = validate_build_completion_authority(
            completion_value,
            completion_path=completion_path,
            receipt_path=rebound_path,
            receipt_raw=rebound_raw,
            receipt_value=rebound_value,
            receipt_stat=rebound_stat,
            expected_cohort_version=validated["cohort_version"],
        )
        final_path, final_raw, final_value, final_stat = (
            load_stable_build_execution_with_stat(path)
        )
        final_completion_path, final_completion_raw, final_completion_value = (
            load_stable_build_completion(completion_expected)
        )
        rebound_identity = (
            rebound_stat.st_dev,
            rebound_stat.st_ino,
            rebound_stat.st_uid,
            rebound_stat.st_gid,
            rebound_stat.st_mode,
            rebound_stat.st_nlink,
            rebound_stat.st_size,
            rebound_stat.st_mtime_ns,
            rebound_stat.st_ctime_ns,
        )
        final_identity = (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_uid,
            final_stat.st_gid,
            final_stat.st_mode,
            final_stat.st_nlink,
            final_stat.st_size,
            final_stat.st_mtime_ns,
            final_stat.st_ctime_ns,
        )
        if (
            final_path != rebound_path
            or final_raw != rebound_raw
            or final_value != rebound_value
            or final_identity != rebound_identity
            or final_completion_path != completion_path
            or final_completion_raw != completion_raw
            or final_completion_value != completion_value
        ):
            raise ValueError("study build receipt or completion changed during validation")
        validated["build_completion"] = completion
        validated["completion_path"] = str(completion_path)
        validated["completion_sha256"] = hashlib.sha256(completion_raw).hexdigest()
        validated["completion_payload_sha256"] = completion["payload_sha256"]
    elif not allow_historical:
        raise ValueError("current study build admission requires schema 5 and its completion")
    return {"path": binding["path"], "sha256": binding["sha256"], **validated}


def _capture_scheduler_environment_contract() -> dict[str, Any]:
    """Return the frozen active-wait scheduler contract used by historical cohorts."""

    return {
        "schema_version": 1,
        "contract": "qcsd-client-rr1-cpu10-v1",
        "scope": "all_measured_neqo_clients",
        "collection_cpuset_cpus": [10, 11],
        "orchestrator_affinity_cpus": [11],
        "client_affinity_cpus": [10],
        "sidecar_affinity_cpus": list(range(10)),
        "policy": "SCHED_RR",
        "priority": 1,
        "rlimit_rtprio": {"soft": 1, "hard": 1},
        "cap_sys_nice": False,
        "docker_cpu_rt_runtime_configured": False,
        "affinity_scope": ("qcsd_container_affinity_partition_not_physical_cpu_isolation"),
    }


def _buflo_etf_capture_scheduler_environment_contract() -> dict[str, Any]:
    """Return the kernel-timed scheduler contract used by fresh cohorts."""

    return {
        "schema_version": 2,
        "contract": "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
        "scope": "all_measured_neqo_clients",
        "collection_cpuset_cpus": [10, 11],
        "orchestrator_affinity_cpus": [11],
        "client_affinity_cpus": [10],
        "timed_egress_helper_affinity_cpus": [11],
        "sidecar_affinity_cpus": list(range(10)),
        "policy": "SCHED_RR",
        "priority": 1,
        "timed_egress_helper_policy": "SCHED_RR",
        "timed_egress_helper_priority": 1,
        "rlimit_rtprio": {"soft": 1, "hard": 1},
        "cap_sys_nice": False,
        "docker_cpu_rt_runtime_configured": False,
        "affinity_scope": ("qcsd_container_affinity_partition_not_physical_cpu_isolation"),
    }


def validate_study_environment_receipt(
    value: Any,
    *,
    expected_image_digest: str | None = None,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Validate the minimized, non-sensitive Docker/build environment receipt."""

    base_keys = {
        "schema_version",
        "artifact_type",
        "docker",
        "collection_image",
        "build_inputs",
        "build_execution",
        "clock_status",
    }
    if not isinstance(value, Mapping) or value.get("schema_version") not in {1, 2, 3}:
        raise ValueError("study environment receipt schema is invalid")
    if value["schema_version"] != 3 and not allow_historical:
        raise ValueError(
            "current study environment admission requires schema 3 and build completion"
        )
    expected_keys = base_keys | (
        {"capture_scheduler"} if value["schema_version"] in {2, 3} else set()
    )
    if set(value) != expected_keys:
        raise ValueError("study environment receipt schema is invalid")
    if value["artifact_type"] != "qcsd-buflo-study-environment":
        raise ValueError("study environment receipt identity is invalid")
    docker = value["docker"]
    if not isinstance(docker, Mapping) or set(docker) != {
        "client_version",
        "server_version",
        "server_os",
        "server_arch",
        "ncpu",
        "mem_total_bytes",
        "storage_driver",
    }:
        raise ValueError("study Docker environment schema is invalid")
    for key in (
        "client_version",
        "server_version",
        "server_os",
        "server_arch",
        "storage_driver",
    ):
        if not isinstance(docker[key], str) or not docker[key]:
            raise ValueError(f"study Docker environment field is invalid: {key}")
    for key in ("ncpu", "mem_total_bytes"):
        if not isinstance(docker[key], int) or isinstance(docker[key], bool) or docker[key] <= 0:
            raise ValueError(f"study Docker capacity field is invalid: {key}")
    if value["schema_version"] in {2, 3} and docker["ncpu"] != 12:
        raise ValueError("study capture scheduler requires the exact 12-CPU topology")

    image = value["collection_image"]
    if not isinstance(image, Mapping) or set(image) != {"id", "repo_digests"}:
        raise ValueError("study collection image schema is invalid")
    image_id = image["id"]
    if (
        not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or len(image_id) != 71
        or any(character not in "0123456789abcdef" for character in image_id[7:])
        or (expected_image_digest is not None and image_id != expected_image_digest)
        or not isinstance(image["repo_digests"], list)
        or any(
            not isinstance(digest, str)
            or "@sha256:" not in digest
            or len(digest.rsplit("@sha256:", 1)[-1]) != 64
            for digest in image["repo_digests"]
        )
    ):
        raise ValueError("study collection image binding is invalid")

    execution = value["build_execution"]
    historical_execution_keys = {"sha256", "receipt"}
    current_execution_keys = historical_execution_keys | {
        "completion_path",
        "completion_sha256",
        "completion_payload_sha256",
        "completion",
    }
    if not isinstance(execution, Mapping) or set(execution) != (
        current_execution_keys if value["schema_version"] == 3 else historical_execution_keys
    ):
        raise ValueError("study no-cache build execution binding is invalid")
    embedded = execution["receipt"]
    encoded_execution = (json.dumps(embedded, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if (
        not isinstance(execution["sha256"], str)
        or execution["sha256"] != hashlib.sha256(encoded_execution).hexdigest()
    ):
        raise ValueError("study no-cache build execution file hash is invalid")
    build_execution = _validate_build_execution_value(
        embedded,
        expected_collection_image=image_id,
        allow_historical=value["schema_version"] in {1, 2} and allow_historical,
    )
    build_completion: dict[str, Any] | None = None
    if value["schema_version"] == 3:
        version = build_execution["cohort_version"]
        expected_completion_path = (
            f"/lab/artifacts/buflo-study/build-completion-v{version}.json"
        )
        expected_receipt_path = Path(
            f"/lab/artifacts/buflo-study/build-execution-v{version}.json"
        )
        completion_value = execution["completion"]
        completion_raw = _canonical_finite_json_bytes(
            completion_value, label="study build completion", newline=True
        )
        if (
            build_execution.get("schema_version") != 5
            or execution.get("completion_path") != expected_completion_path
            or not isinstance(execution.get("completion_sha256"), str)
            or execution["completion_sha256"]
            != hashlib.sha256(completion_raw).hexdigest()
            or not isinstance(execution.get("completion_payload_sha256"), str)
        ):
            raise ValueError("study build completion binding is invalid")
        completion_binding = completion_value.get("receipt") if isinstance(
            completion_value, Mapping
        ) else None
        if not isinstance(completion_binding, Mapping):
            raise ValueError("study build completion receipt binding is invalid")
        build_completion = validate_build_completion_authority(
            completion_value,
            completion_path=Path(expected_completion_path),
            receipt_path=expected_receipt_path,
            receipt_raw=encoded_execution,
            receipt_value=embedded,
            receipt_stat=completion_binding.get("stat"),
            expected_cohort_version=version,
        )
        if (
            build_completion["payload_sha256"]
            != execution["completion_payload_sha256"]
        ):
            raise ValueError("study build completion payload binding is invalid")

    build = value["build_inputs"]
    if not isinstance(build, Mapping) or set(build) != {
        "schema_version",
        "artifact_type",
        "rust_base_image",
        "debian_base_image",
        "uv_lock_sha256",
        "cargo_lock_sha256",
    }:
        raise ValueError("study build input receipt schema is invalid")
    historical_environment = value["schema_version"] in {1, 2} and allow_historical
    if (
        build["schema_version"] != 1
        or build["artifact_type"] != "qcsd-study-build-inputs"
        or build != embedded.get("build_inputs")
        or (
            not historical_environment
            and (
                build["rust_base_image"] != RUST_BASE_IMAGE
                or build["debian_base_image"] != DEBIAN_BASE_IMAGE
                or build["uv_lock_sha256"] != sha256_file(LAB_ROOT / "uv.lock")
                or build["cargo_lock_sha256"]
                != sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock")
            )
        )
    ):
        raise ValueError("study base image or lockfile binding is invalid")
    clock = value["clock_status"]
    if (
        not isinstance(clock, Mapping)
        or set(clock) != {"relationship", "host", "container"}
        or clock.get("relationship") != "container-shares-host-kernel-realtime-clock"
    ):
        raise ValueError("study host/container clock-status receipt is invalid")
    for label in ("host", "container"):
        record = clock[label]
        if (
            not isinstance(record, Mapping)
            or set(record)
            != {
                "source",
                "synchronized",
                "status_evidence",
                "unavailable_reason",
                "realtime_unix_ns",
                "monotonic_ns",
            }
            or not isinstance(record.get("source"), str)
            or not record["source"]
            or record.get("synchronized") not in {True, False, None}
            or type(record.get("realtime_unix_ns")) is not int
            or record["realtime_unix_ns"] <= 0
            or type(record.get("monotonic_ns")) is not int
            or record["monotonic_ns"] <= 0
        ):
            raise ValueError(f"study {label} clock-status evidence is invalid")
        if record["synchronized"] is None:
            if (
                record.get("status_evidence") is not None
                or not isinstance(record.get("unavailable_reason"), str)
                or not record["unavailable_reason"].strip()
            ):
                raise ValueError(f"study {label} clock-status unavailability is unreceipted")
        elif (
            not isinstance(record.get("status_evidence"), str)
            or not record["status_evidence"].strip()
            or record.get("unavailable_reason") is not None
        ):
            raise ValueError(f"study {label} clock synchronization status is malformed")
    if (
        abs(clock["host"]["realtime_unix_ns"] - clock["container"]["realtime_unix_ns"])
        > 60_000_000_000
    ):
        raise ValueError("study host/container realtime samples differ by more than 60 seconds")
    capture_scheduler = value.get("capture_scheduler")
    historical_capture_scheduler = _capture_scheduler_environment_contract()
    kernel_timed_capture_scheduler = _buflo_etf_capture_scheduler_environment_contract()
    if value["schema_version"] in {2, 3} and capture_scheduler not in (
        historical_capture_scheduler,
        kernel_timed_capture_scheduler,
    ):
        raise ValueError("study capture scheduler environment receipt is invalid")
    validated = {
        "schema_version": value["schema_version"],
        "image_id": image_id,
        "docker": dict(docker),
        "build_inputs": dict(build),
        "build_execution": {
            "sha256": execution["sha256"],
            **build_execution,
        },
        "clock_status": {
            "relationship": clock["relationship"],
            "host": dict(clock["host"]),
            "container": dict(clock["container"]),
        },
    }
    if value["schema_version"] == 3:
        assert build_completion is not None
        validated["build_execution"].update(
            {
                "completion_path": execution["completion_path"],
                "completion_sha256": execution["completion_sha256"],
                "completion_payload_sha256": execution[
                    "completion_payload_sha256"
                ],
                "build_completion": build_completion,
            }
        )
    if value["schema_version"] in {2, 3}:
        validated["capture_scheduler"] = dict(capture_scheduler)
    return validated


def _one_build_execution_identity(
    environments: Sequence[Mapping[str, Any]],
    *,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Require every evidence cohort to originate in one no-cache build.

    Current operational evidence is completion-bound by default.  The
    historical branch is explicit so immutable schema-1/2 environments remain
    inspectable without making a downgrade admissible to a new campaign.
    """

    identities = []
    for environment in environments:
        build = environment.get("build_execution")
        legacy_identity = (
            isinstance(build, Mapping)
            and type(build.get("cohort_version")) is int
            and build["cohort_version"] >= 1
            and isinstance(build.get("sha256"), str)
            and isinstance(build.get("collection_image"), str)
            and isinstance(build.get("started_at"), str)
            and isinstance(build.get("finished_at"), str)
        )
        if (
            not isinstance(build, Mapping)
            or not legacy_identity
            or not isinstance(build.get("completion_path"), str)
            or not re.fullmatch(
                r"/lab/artifacts/buflo-study/build-completion-v[1-9][0-9]*[.]json",
                build["completion_path"],
            )
            or not isinstance(build.get("completion_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", build["completion_sha256"]) is None
        ):
            if not allow_historical or not legacy_identity:
                raise ValueError("study evidence has no typed no-cache build identity")
            identities.append(
                {
                    "cohort_version": build["cohort_version"],
                    "sha256": build["sha256"],
                    "collection_image": build["collection_image"],
                    "started_at": build["started_at"],
                    "finished_at": build["finished_at"],
                }
            )
        else:
            identities.append(
                {
                    "cohort_version": build["cohort_version"],
                    "sha256": build["sha256"],
                    "completion_path": build["completion_path"],
                    "completion_sha256": build["completion_sha256"],
                    "collection_image": build["collection_image"],
                    "started_at": build["started_at"],
                    "finished_at": build["finished_at"],
                }
            )
    if not identities or any(identity != identities[0] for identity in identities[1:]):
        raise ValueError("study evidence was not produced by one exact no-cache build")
    return identities[0]


def validate_staged_capture_prerequisites(
    stage: str,
    result_roots: Sequence[Path],
    *,
    expected_cohort_version: int = 1,
) -> dict[str, Any]:
    """Require the exact earlier cohorts before exposing a public capture stage."""

    version = _cohort_version(expected_cohort_version)
    prerequisites = STAGED_CAPTURE_PREREQUISITES.get(stage)
    if prerequisites is None:
        raise ValueError("staged capture prerequisites require smoke, rehearsal, or formal")
    roots_by_name = _result_roots_by_declared_name(result_roots)
    expected_names = set(LOCAL_STAGE_RESULT_NAMES["regression"])
    for prerequisite in prerequisites:
        if prerequisite in {"smoke", "rehearsal"}:
            expected_names.add(_public_campaign_name(prerequisite))
    if set(roots_by_name) != expected_names:
        missing = sorted(expected_names - set(roots_by_name))
        extra = sorted(set(roots_by_name) - expected_names)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise ValueError(
            f"{stage} staged capture evidence is not the exact prerequisite set: "
            + "; ".join(details)
        )

    regression = validate_regression_results(
        tuple(roots_by_name[name] for name in LOCAL_STAGE_RESULT_NAMES["regression"])
    )
    public: dict[str, Any] = {}
    for prerequisite in prerequisites:
        if prerequisite in {"smoke", "rehearsal"}:
            name = _public_campaign_name(prerequisite)
            public[prerequisite] = _validate_public_stage_result(
                prerequisite,
                roots_by_name[name],
                expected_cohort_version=version,
            )
    sources = [regression["source"], *(record["source"] for record in public.values())]
    lineage = _require_one_current_clean_source(sources)
    return {
        "schema_version": 1,
        "requested_stage": stage,
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
        "prerequisites": list(prerequisites),
        "regression": regression,
        "public": public,
        "source": lineage,
        "samples": regression["samples"] + sum(record["samples"] for record in public.values()),
        "authoritative_bytes": regression["authoritative_bytes"]
        + sum(record["authoritative_bytes"] for record in public.values()),
    }


def validate_formal_capture_capacity(
    staged: Mapping[str, Any],
    *,
    available_window_hours: float | None,
    results_root: Path = LAB_ROOT / "results",
) -> dict[str, Any]:
    """Admit formal capture only with a declared window and threefold free space."""

    if (
        not isinstance(available_window_hours, (int, float))
        or isinstance(available_window_hours, bool)
        or not math.isfinite(float(available_window_hours))
        or float(available_window_hours) < FORMAL_MINIMUM_AVAILABLE_HOURS
    ):
        raise ValueError(
            "formal capture requires --formal-window-hours of at least "
            f"{FORMAL_MINIMUM_AVAILABLE_HOURS:g}"
        )
    public = staged.get("public")
    if not isinstance(public, Mapping) or set(public) != {"smoke", "rehearsal"}:
        raise ValueError("formal capacity projection requires verified smoke and rehearsal")
    observed_samples = sum(record["samples"] for record in public.values())
    observed_bytes = sum(record["authoritative_bytes"] for record in public.values())
    if observed_samples != 60 or observed_bytes <= 0:
        raise ValueError("formal capacity projection basis is invalid")
    rehearsal = public["rehearsal"]
    rehearsal_elapsed = rehearsal.get("elapsed_seconds")
    if (
        not isinstance(rehearsal_elapsed, (int, float))
        or isinstance(rehearsal_elapsed, bool)
        or not math.isfinite(float(rehearsal_elapsed))
        or float(rehearsal_elapsed) <= 0
    ):
        raise ValueError("formal capacity projection requires measured rehearsal elapsed time")
    formal_samples = load_study_plan()["public_stages"]["formal"]["expected_samples"]
    projected_bytes = (observed_bytes * formal_samples + observed_samples - 1) // observed_samples
    measured_projection_seconds = math.ceil(
        float(rehearsal_elapsed) * formal_samples / int(rehearsal["samples"])
    )
    minimum_cooldown_seconds = formal_samples * COMMON_LIMITS["per_origin_cooldown_seconds"]
    expected_wall_seconds = max(minimum_cooldown_seconds, measured_projection_seconds)
    conservative_upper_seconds = expected_wall_seconds + formal_samples * (
        COMMON_LIMITS["settle_seconds"]
        + (COMMON_LIMITS["max_attempts"] - 1) * COMMON_LIMITS["timeout_seconds"]
    )
    available_window_seconds = float(available_window_hours) * 3_600
    if available_window_seconds < expected_wall_seconds:
        raise ValueError(
            "formal capture window is below the rehearsal-derived expected wall time: "
            f"{available_window_seconds:g}s available, {expected_wall_seconds:g}s expected"
        )
    required_free_bytes = projected_bytes * FORMAL_DISK_SAFETY_MULTIPLIER
    results_root = results_root.resolve()
    if results_root.is_symlink() or not results_root.is_dir():
        raise ValueError(f"formal result root is not a regular directory: {results_root}")
    free_bytes = shutil.disk_usage(results_root).free
    if free_bytes < required_free_bytes:
        raise ValueError(
            "formal capture has insufficient free disk: "
            f"{free_bytes} available, {required_free_bytes} required"
        )
    return {
        "schema_version": 1,
        "available_window_hours": float(available_window_hours),
        "available_window_seconds": available_window_seconds,
        "minimum_available_hours": FORMAL_MINIMUM_AVAILABLE_HOURS,
        "minimum_sequential_cooldown_seconds": minimum_cooldown_seconds,
        "rehearsal_elapsed_seconds": float(rehearsal_elapsed),
        "rehearsal_samples": int(rehearsal["samples"]),
        "measured_projection_seconds": measured_projection_seconds,
        "expected_formal_wall_seconds": expected_wall_seconds,
        "expected_formal_wall_hours": expected_wall_seconds / 3_600,
        "conservative_upper_seconds": conservative_upper_seconds,
        "projection_assumptions": {
            "acquisition_basis": "verified-rehearsal-started-at-to-completed-at",
            "captures_are_serial": True,
            "observed_projection_includes_realized_settle-cooldown-and-retries": True,
            "upper_adds_two-timeout-attempts-and-one-settle-per-formal-sample": True,
        },
        "projection_samples": observed_samples,
        "projection_authoritative_bytes": observed_bytes,
        "formal_samples": formal_samples,
        "projected_formal_bytes": projected_bytes,
        "disk_safety_multiplier": FORMAL_DISK_SAFETY_MULTIPLIER,
        "required_free_bytes": required_free_bytes,
        "available_free_bytes": free_bytes,
        "results_root": str(results_root),
        "docker_capacity": _formal_docker_capacity_disclosure(staged),
    }


def _formal_docker_capacity_disclosure(staged: Mapping[str, Any]) -> dict[str, Any]:
    """Receipt the Docker dimensions available without inventing unsupported gates."""

    public = staged.get("public")
    if not isinstance(public, Mapping) or not isinstance(public.get("rehearsal"), Mapping):
        raise ValueError("formal Docker capacity disclosure requires rehearsal evidence")
    environment = public["rehearsal"].get("environment")
    docker = environment.get("docker") if isinstance(environment, Mapping) else None
    required = ("ncpu", "mem_total_bytes", "storage_driver")
    has_docker = isinstance(docker, Mapping) and all(key in docker for key in required)
    return {
        "observed_rehearsal_daemon": (
            {key: docker[key] for key in required} if has_docker else None
        ),
        "compute_gate": {
            "status": "recorded-not-thresholded" if has_docker else "unavailable",
            "reason": (
                "the capture plan defines no CPU-count acceptance threshold"
                if has_docker
                else "the supplied projection basis has no typed Docker daemon capacity"
            ),
        },
        "memory_gate": {
            "status": "unavailable",
            "reason": (
                "the sealed rehearsal does not contain a defensible per-container peak-memory "
                "projection; daemon total memory is provenance only"
            ),
        },
        "container_storage_gate": {
            "status": "not-applicable",
            "reason": (
                "authoritative results use the host bind mount; the enforced host free-space "
                "gate is the rehearsal-derived 3x projection"
            ),
        },
    }


def _validate_formal_capture_capacity_record(
    staged: Mapping[str, Any],
    value: Mapping[str, Any],
    *,
    available_window_hours: float | None,
    results_root: Path,
) -> dict[str, Any]:
    """Recompute an admission-time capacity receipt without reusing mutable free space."""

    if not isinstance(value, Mapping) or type(value.get("available_free_bytes")) is not int:
        raise ValueError("formal capacity receipt is malformed")
    public = staged.get("public")
    if not isinstance(public, Mapping) or set(public) != {"smoke", "rehearsal"}:
        raise ValueError("formal capacity receipt requires verified public prerequisites")
    rehearsal = public["rehearsal"]
    observed_samples = sum(int(record["samples"]) for record in public.values())
    observed_bytes = sum(int(record["authoritative_bytes"]) for record in public.values())
    formal_samples = load_study_plan()["public_stages"]["formal"]["expected_samples"]
    rehearsal_elapsed = float(rehearsal["elapsed_seconds"])
    projected_bytes = (observed_bytes * formal_samples + observed_samples - 1) // observed_samples
    measured_projection_seconds = math.ceil(
        rehearsal_elapsed * formal_samples / int(rehearsal["samples"])
    )
    minimum_cooldown_seconds = formal_samples * COMMON_LIMITS["per_origin_cooldown_seconds"]
    expected_wall_seconds = max(minimum_cooldown_seconds, measured_projection_seconds)
    conservative_upper_seconds = expected_wall_seconds + formal_samples * (
        COMMON_LIMITS["settle_seconds"]
        + (COMMON_LIMITS["max_attempts"] - 1) * COMMON_LIMITS["timeout_seconds"]
    )
    window = float(available_window_hours) if available_window_hours is not None else math.nan
    required_free_bytes = projected_bytes * FORMAL_DISK_SAFETY_MULTIPLIER
    expected = {
        "schema_version": 1,
        "available_window_hours": window,
        "available_window_seconds": window * 3_600,
        "minimum_available_hours": FORMAL_MINIMUM_AVAILABLE_HOURS,
        "minimum_sequential_cooldown_seconds": minimum_cooldown_seconds,
        "rehearsal_elapsed_seconds": rehearsal_elapsed,
        "rehearsal_samples": int(rehearsal["samples"]),
        "measured_projection_seconds": measured_projection_seconds,
        "expected_formal_wall_seconds": expected_wall_seconds,
        "expected_formal_wall_hours": expected_wall_seconds / 3_600,
        "conservative_upper_seconds": conservative_upper_seconds,
        "projection_assumptions": {
            "acquisition_basis": "verified-rehearsal-started-at-to-completed-at",
            "captures_are_serial": True,
            "observed_projection_includes_realized_settle-cooldown-and-retries": True,
            "upper_adds_two-timeout-attempts-and-one-settle-per-formal-sample": True,
        },
        "projection_samples": observed_samples,
        "projection_authoritative_bytes": observed_bytes,
        "formal_samples": formal_samples,
        "projected_formal_bytes": projected_bytes,
        "disk_safety_multiplier": FORMAL_DISK_SAFETY_MULTIPLIER,
        "required_free_bytes": required_free_bytes,
        "available_free_bytes": int(value["available_free_bytes"]),
        "results_root": str(results_root.resolve()),
        "docker_capacity": _formal_docker_capacity_disclosure(staged),
    }
    if (
        not math.isfinite(window)
        or window < FORMAL_MINIMUM_AVAILABLE_HOURS
        or window * 3_600 < expected_wall_seconds
        or expected["available_free_bytes"] < required_free_bytes
        or dict(value) != expected
    ):
        raise ValueError("formal capacity receipt projections or admission are invalid")
    return expected


def _report_frozen_formal_prelaunch(capacity: Mapping[str, Any]) -> None:
    """Expose the admission-frozen wall/storage estimate without polluting JSON stdout."""

    print(
        "formal capture frozen estimate: "
        f"expected={capacity['expected_formal_wall_hours']:.3f}h; "
        f"conservative_upper={capacity['conservative_upper_seconds'] / 3_600:.3f}h; "
        f"projected={capacity['projected_formal_bytes']} bytes; "
        f"3x_required={capacity['required_free_bytes']} bytes",
        file=sys.stderr,
        flush=True,
    )


def _validate_local_stage_results(
    stage: str,
    result_roots: Sequence[Path],
    *,
    explanation_receipt: Path | None = None,
    _expected_collection_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if stage not in {"controlled", "regression"}:
        raise ValueError("local stage result validation requires controlled or regression")

    from .verification import verify_result

    expected = {
        _canonical_digest({key: value for key, value in cell.items() if key != "sample_index"})
        for cell in generated_stage_cells(stage)
    }
    expected_names = set(LOCAL_STAGE_RESULT_NAMES[stage])
    observed_names: set[str] = set()
    observed: set[str] = set()
    bindings = []
    sources = []
    authoritative_bytes = 0
    capacity_samples: list[dict[str, Any]] = []
    multi_endpoint_samples: list[dict[str, Any]] = []
    controlled_costs: dict[tuple[str, str, int], dict[str, dict[str, int]]] = {}
    regression_receipts: list[dict[str, Any]] = []
    for root in result_roots:
        verified = verify_result(Path(root))
        name = verified.experiment["name"]
        if name not in expected_names or name in observed_names:
            raise ValueError(f"{stage} result identities are not the exact frozen set")
        observed_names.add(name)
        if verified.experiment["status"] != "complete":
            raise ValueError(f"{stage} result is not complete: {root}")
        expected_samples = (
            40
            if stage == "controlled"
            else {
                "buflo-study-v1-regression-established-seven-1200": 14,
                "buflo-study-v1-regression-buflo-1200": 2,
                "buflo-study-v1-regression-cs-buflo-1200": 2,
            }[name]
        )
        if len(verified.accepted_samples) != expected_samples:
            raise ValueError(f"{stage} result {name} has the wrong accepted sample count")
        source = verified.experiment.get("source")
        _validate_clean_source(source, label=f"{stage} result {name}")
        environment = _validate_result_environment(verified, source)
        sources.append(source)
        if stage == "regression":
            campaign_path = verified.root / "inputs/campaign.yml"
            if campaign_path.is_symlink() or not campaign_path.is_file():
                raise ValueError("regression result lacks its frozen campaign")
            campaign = yaml.safe_load(campaign_path.read_text(encoding="utf-8"))
            controlled = campaign.get("study_controlled") if isinstance(campaign, Mapping) else None
            regression_receipts.append(
                validate_controlled_campaign_receipt(
                    controlled,
                    _expected_collection_source=_expected_collection_source,
                )
            )
        result_bytes = _verified_result_bytes(verified)
        authoritative_bytes += result_bytes
        bindings.append(
            {
                "root": str(verified.root),
                "name": name,
                "evidence_sha256": sha256_file(verified.root / "evidence.sha256"),
                "samples": len(verified.accepted_samples),
                "campaign_sha256": verified.experiment["configuration"]["campaign_sha256"],
                "authoritative_bytes": result_bytes,
                "environment": environment,
            }
        )
        for sample in verified.experiment["samples"]:
            if sample.get("state") != "accepted":
                continue
            diagnostics = sample.get("diagnostics")
            cell = (
                diagnostics.get("buflo_study_controlled_cell")
                if isinstance(diagnostics, Mapping)
                else None
            )
            if not isinstance(cell, Mapping) or set(cell) != {
                "workload",
                "visit",
                "treatment",
                "treatment_position",
                "netem_profile",
                "client_qdisc",
                "server_qdisc",
            }:
                raise ValueError(f"{stage} sample has no exact netem/cell receipt")
            if (
                sample.get("eligible") is not True
                or diagnostics.get("fidelity_eligible") is not True
            ):
                raise ValueError(f"{stage} sample is not correctness/fidelity eligible")
            digest = _canonical_digest(dict(cell))
            if digest in observed:
                raise ValueError(f"{stage} matrix contains a duplicate cell")
            observed.add(digest)
            if stage == "controlled":
                evidence = _controlled_sample_capacity_and_cost(
                    verified.root / str(sample["path"]),
                    cell,
                )
                if cell["netem_profile"] == "clean" and cell["treatment"] in {
                    "buflo",
                    "cs-buflo-ctsp",
                    "cs-buflo-cpsp",
                }:
                    capacity_samples.append(evidence)
                if cell["workload"] == "local-large" and cell["treatment"] in {
                    "buflo",
                    "cs-buflo-ctsp",
                    "cs-buflo-cpsp",
                }:
                    multi_endpoint_samples.append(evidence)
                key = (
                    str(cell["netem_profile"]),
                    str(cell["workload"]),
                    int(cell["visit"]),
                )
                controlled_costs.setdefault(key, {})[str(cell["treatment"])] = {
                    "wire_bytes": evidence["wire_bytes"],
                    "udp_payload_bytes": evidence["udp_payload_bytes"],
                }
    expected_count = 160 if stage == "controlled" else 18
    if observed_names != expected_names or observed != expected or len(observed) != expected_count:
        raise ValueError(
            f"{stage} evidence does not exactly cover the frozen {expected_count} cells"
        )
    lineage = _require_one_current_clean_source(
        sources,
        expected_source=_expected_collection_source,
    )
    result = {
        "schema_version": 1,
        "samples": len(observed),
        "authoritative_bytes": authoritative_bytes,
        "source": lineage,
        "results": bindings,
    }
    if stage == "controlled":
        result["sustained_cell_capacity"] = _validate_sustained_cell_capacity(capacity_samples)
        result["multiple_endpoint_coverage"] = _validate_controlled_multi_endpoint_coverage(
            multi_endpoint_samples
        )
        result["ctsp_cpsp_ordering"] = _validate_ctsp_cpsp_ordering(
            controlled_costs,
            evidence_sha256s=[item["evidence_sha256"] for item in bindings],
            explanation_receipt=explanation_receipt,
        )
    else:
        result["established_seven_baseline"] = validate_established_seven_baseline()
        destinations = {Path(binding["root"]).resolve().parents[2] for binding in bindings}
        if len(destinations) != 1:
            raise ValueError("regression shards do not share one compatibility root")
        [destination] = destinations
        timing_stress = _validate_current_regression_timing_stress(
            regression_receipts,
            destination=destination,
            lineage=lineage,
            expected_source=lineage,
        )
        compatibility = validate_regression_multi_origin_compatibility(
            destination / "multi-origin-nine-mode-compatibility/receipt.json",
            result_roots,
            _expected_collection_source=lineage,
        )
        if compatibility["source"] != lineage:
            raise ValueError("regression compatibility source differs from the 18-sample shards")
        result["buflo_timing_stress"] = timing_stress
        result["multi_origin_nine_mode_compatibility"] = compatibility
    return result


def _controlled_sample_capacity_and_cost(
    sample_path: Path, cell: Mapping[str, Any]
) -> dict[str, Any]:
    from .buflo_handoff import _algorithm_diagnostics
    from .capture import extract_trace
    from .fidelity import _schedule_realization_metrics

    if sample_path.is_symlink() or not sample_path.is_dir():
        raise ValueError("controlled sample path is not a regular directory")
    run_path = sample_path / "neqo/run.json"
    run = load_json(run_path)
    endpoints = run.get("endpoints") if isinstance(run, Mapping) else None
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("controlled sample has no endpoint binding")
    endpoint_coverage = _controlled_endpoint_coverage(
        endpoints,
        workload=str(cell["workload"]),
    )
    trace = extract_trace(sample_path / "capture.pcapng", endpoints)
    if not trace or any(packet.udp_payload_len is None for packet in trace):
        raise ValueError("controlled sample has incomplete observer UDP evidence")
    schedule = _schedule_realization_metrics(sample_path)
    diagnostics = run.get("defense_diagnostics")
    if not isinstance(diagnostics, Mapping):
        diagnostics = {}
    treatment = str(cell["treatment"])
    capacity: dict[str, Any] | None = None
    algorithm = None
    if treatment in {"buflo", "cs-buflo-ctsp", "cs-buflo-cpsp"}:
        runtime_kind = "buflo" if treatment == "buflo" else "cs_buflo"
        algorithm = _algorithm_diagnostics(
            run,
            defense=treatment,
            runtime_kind=runtime_kind,
            schedule_path=sample_path / "neqo/schedule.csv",
            events_path=sample_path / "neqo/events.csv",
            packets_path=sample_path / "neqo/packets.csv",
        )
    if treatment == "buflo":
        terminal_subcell = algorithm.get("buflo_state") if isinstance(algorithm, Mapping) else None
        targets = schedule.get("target_times_us_by_direction")
        sizes = schedule.get("scheduled_sizes_by_direction")
        capacity = {
            "cell_size_bytes": 1_200,
            "minimum_interval_us": 20_000,
            "outgoing_opportunities": schedule.get("scheduled_outgoing_events"),
            "incoming_opportunities": schedule.get("scheduled_incoming_events"),
            "outgoing_full_cells": diagnostics.get("buflo_full_outgoing_cells"),
            "incoming_consumed_bytes": diagnostics.get("scheduled_incoming_consumed_bytes"),
            "incoming_advertised_bytes": diagnostics.get("scheduled_incoming_advertised_bytes"),
            "incoming_terminal_cells": schedule.get("incoming_credit_consumed_events"),
            "incoming_consumption_delay_us_max": schedule.get(
                "incoming_credit_consumption_delay_us_max"
            ),
            "runner_full_extended_schema_validated": algorithm is not None,
            "runner_algorithm_evidence_sha256": _canonical_digest(algorithm),
            "terminal_subcell": terminal_subcell,
            "minimum_interval_exercised": all(
                isinstance(targets, Mapping)
                and isinstance(targets.get(direction), list)
                and len(targets[direction]) > 1
                and any(
                    current - previous == 20_000
                    for previous, current in pairwise(targets[direction])
                )
                for direction in ("outgoing", "incoming")
            ),
            "exact_target_sizes": bool(
                isinstance(sizes, Mapping)
                and all(
                    isinstance(sizes.get(direction), list)
                    and sizes[direction]
                    and set(sizes[direction]) == {1_200}
                    for direction in ("outgoing", "incoming")
                )
            ),
            "no_unresolved_credit": (
                diagnostics.get("scheduled_incoming_unresolved_bytes") == 0
                and diagnostics.get("buflo_outgoing_unresolved_cells") == 0
                and diagnostics.get("buflo_incoming_unresolved_cells") == 0
            ),
        }
        capacity["passed"] = bool(
            capacity["minimum_interval_exercised"]
            and capacity["exact_target_sizes"]
            and type(capacity["outgoing_opportunities"]) is int
            and capacity["outgoing_opportunities"] > 0
            and type(capacity["incoming_opportunities"]) is int
            and capacity["incoming_opportunities"] > 0
            and capacity["outgoing_full_cells"] == capacity["outgoing_opportunities"]
            and capacity["incoming_consumed_bytes"] == capacity["incoming_opportunities"] * 1_200
            and capacity["incoming_advertised_bytes"] == capacity["incoming_consumed_bytes"]
            and capacity["incoming_terminal_cells"] == capacity["incoming_opportunities"]
            and capacity["no_unresolved_credit"]
            and _controlled_buflo_terminal_subcell_valid(terminal_subcell)
        )
    elif treatment in {"cs-buflo-ctsp", "cs-buflo-cpsp"}:
        sizes = schedule.get("scheduled_sizes_by_direction")
        rate_driver = _controlled_csbuflo_rate_driver_observation(str(cell["workload"]), run)

        def minimum_exercised(direction: str) -> bool:
            opportunities = diagnostics.get(f"cs_buflo_{direction}_minimum_interval_opportunities")
            terminal = diagnostics.get(f"cs_buflo_{direction}_minimum_interval_terminal")
            full = diagnostics.get(f"cs_buflo_{direction}_minimum_interval_full")
            common = bool(
                diagnostics.get(f"cs_buflo_{direction}_interval_us") == 4_096
                and type(opportunities) is int
                and opportunities > 0
                and opportunities == terminal == full
            )
            if direction == "incoming":
                return bool(
                    common
                    and diagnostics.get("cs_buflo_incoming_minimum_interval_local_realized")
                    == opportunities
                )
            return common

        capacity = {
            "cell_size_bytes": 600,
            "minimum_interval_us": 4_096,
            "outgoing_opportunities": schedule.get("scheduled_outgoing_events"),
            "incoming_opportunities": schedule.get("scheduled_incoming_events"),
            "outgoing_full_cells": diagnostics.get("cs_buflo_full_outgoing_cells"),
            "incoming_consumed_bytes": diagnostics.get("scheduled_incoming_consumed_bytes"),
            "incoming_advertised_bytes": diagnostics.get("scheduled_incoming_advertised_bytes"),
            "incoming_terminal_cells": schedule.get("incoming_credit_consumed_events"),
            "incoming_consumption_delay_us_max": schedule.get(
                "incoming_credit_consumption_delay_us_max"
            ),
            "runner_full_extended_schema_validated": algorithm is not None,
            "runner_algorithm_evidence_sha256": _canonical_digest(algorithm),
            "incoming_local_realized_cells": diagnostics.get(
                "cs_buflo_incoming_local_realized_cells"
            ),
            "minimum_interval_exercised": all(
                minimum_exercised(direction) for direction in ("outgoing", "incoming")
            ),
            **{
                f"{direction}_minimum_interval_{field}": diagnostics.get(
                    f"cs_buflo_{direction}_minimum_interval_{field}"
                )
                for direction in ("outgoing", "incoming")
                for field in ("opportunities", "terminal", "full")
            },
            "incoming_minimum_interval_local_realized": diagnostics.get(
                "cs_buflo_incoming_minimum_interval_local_realized"
            ),
            "request_rate_driver_resource_id": rate_driver["resource_id"],
            "request_rate_driver_request_stream_bytes": rate_driver["request_stream_bytes"],
            "request_rate_driver_boundary_bytes": rate_driver["boundary_bytes"],
            "request_rate_driver_post_boundary_cells": rate_driver["post_boundary_cells"],
            "exact_target_sizes": bool(
                isinstance(sizes, Mapping)
                and all(
                    isinstance(sizes.get(direction), list)
                    and sizes[direction]
                    and set(sizes[direction]) == {600}
                    for direction in ("outgoing", "incoming")
                )
            ),
            "no_unresolved_credit": (
                diagnostics.get("scheduled_incoming_unresolved_bytes") == 0
                and diagnostics.get("cs_buflo_outgoing_unresolved_cells") == 0
                and diagnostics.get("cs_buflo_incoming_unresolved_cells") == 0
            ),
        }
        capacity["passed"] = bool(
            capacity["minimum_interval_exercised"]
            and capacity["exact_target_sizes"]
            and type(capacity["outgoing_opportunities"]) is int
            and capacity["outgoing_opportunities"] > 0
            and type(capacity["incoming_opportunities"]) is int
            and capacity["incoming_opportunities"] > 0
            and type(capacity["outgoing_full_cells"]) is int
            and capacity["outgoing_full_cells"] == capacity["outgoing_opportunities"]
            and diagnostics.get("cs_buflo_partial_outgoing_cells") == 0
            and diagnostics.get("cs_buflo_suppressed_outgoing_cells") == 0
            and capacity["incoming_consumed_bytes"] == capacity["incoming_opportunities"] * 600
            and capacity["incoming_advertised_bytes"] == capacity["incoming_consumed_bytes"]
            and capacity["incoming_terminal_cells"] == capacity["incoming_opportunities"]
            and capacity["incoming_local_realized_cells"] == capacity["incoming_opportunities"]
            and capacity["request_rate_driver_request_stream_bytes"]
            >= CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
            and capacity["request_rate_driver_post_boundary_cells"]
            >= CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS
            and capacity["no_unresolved_credit"]
        )
    return {
        "treatment": treatment,
        "workload": str(cell["workload"]),
        "visit": int(cell["visit"]),
        "netem_profile": str(cell["netem_profile"]),
        "wire_bytes": sum(packet.frame_len for packet in trace),
        "udp_payload_bytes": sum(int(packet.udp_payload_len) for packet in trace),
        "endpoint_coverage": endpoint_coverage,
        "capacity": capacity,
    }


def _controlled_endpoint_coverage(endpoints: Sequence[Any], *, workload: str) -> dict[str, Any]:
    """Bind each controlled sample to its exact live endpoint set."""

    from .manifest import https_origin

    expected_by_workload = {
        "local-small": ("https://qcsd-buflo-server-one:4433",),
        "local-large": (
            "https://qcsd-buflo-server-one:4433",
            "https://qcsd-buflo-server-two:4434",
        ),
    }
    expected = expected_by_workload.get(workload)
    if expected is None:
        raise ValueError("controlled endpoint coverage has an unknown workload")
    observed_ids: list[int] = []
    observed_origins: list[str] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            raise ValueError("controlled endpoint coverage contains a non-object endpoint")
        endpoint_id = endpoint.get("id")
        origin = endpoint.get("origin")
        canonical_origin = https_origin(origin) if isinstance(origin, str) else None
        if type(endpoint_id) is not int or endpoint_id < 0 or canonical_origin is None:
            raise ValueError("controlled endpoint coverage identity is invalid")
        observed_ids.append(endpoint_id)
        observed_origins.append(canonical_origin)
    if (
        sorted(observed_ids) != list(range(len(expected)))
        or len(set(observed_origins)) != len(observed_origins)
        or tuple(sorted(observed_origins)) != tuple(sorted(expected))
    ):
        raise ValueError("controlled sample does not bind the exact expected endpoint set")
    return {
        "schema_version": 1,
        "workload": workload,
        "expected_endpoint_count": len(expected),
        "observed_endpoint_count": len(endpoints),
        "expected_origins": list(expected),
        "observed_origins": sorted(observed_origins),
        "passed": True,
    }


def _validate_controlled_multi_endpoint_coverage(
    values: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Require every new defense on every profile to exercise both origins."""

    treatments = ("buflo", "cs-buflo-ctsp", "cs-buflo-cpsp")
    profiles = tuple(profile["id"] for profile in load_study_plan()["controlled"]["netem_profiles"])
    expected = {
        (treatment, profile, visit)
        for treatment in treatments
        for profile in profiles
        for visit in range(5)
    }
    observed = {
        (str(value["treatment"]), str(value["netem_profile"]), int(value["visit"]))
        for value in values
    }
    expected_origins = [
        "https://qcsd-buflo-server-one:4433",
        "https://qcsd-buflo-server-two:4434",
    ]
    if observed != expected or len(values) != len(expected):
        raise ValueError("controlled multi-endpoint evidence does not cover all 60 cells")
    for value in values:
        coverage = value.get("endpoint_coverage")
        if not isinstance(coverage, Mapping) or dict(coverage) != {
            "schema_version": 1,
            "workload": "local-large",
            "expected_endpoint_count": 2,
            "observed_endpoint_count": 2,
            "expected_origins": expected_origins,
            "observed_origins": expected_origins,
            "passed": True,
        }:
            raise ValueError("controlled multi-endpoint evidence is invalid")
    return {
        "schema_version": 1,
        "samples": len(values),
        "workload": "local-large",
        "endpoint_count": 2,
        "origins": expected_origins,
        "profiles": list(profiles),
        "treatments": {
            treatment: sum(value["treatment"] == treatment for value in values)
            for treatment in treatments
        },
        "passed": True,
    }


def _validate_sustained_cell_capacity(values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    expected = {
        (treatment, workload, visit)
        for treatment in ("buflo", "cs-buflo-ctsp", "cs-buflo-cpsp")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    }
    observed = {
        (str(value["treatment"]), str(value["workload"]), int(value["visit"])) for value in values
    }
    if observed != expected or len(values) != len(expected):
        raise ValueError("controlled clean capacity evidence does not cover all 30 cells")

    def capacity_is_valid(value: Mapping[str, Any]) -> bool:
        treatment = str(value["treatment"])
        capacity = value.get("capacity")
        if not isinstance(capacity, Mapping) or capacity.get("passed") is not True:
            return False
        cell_size = 1_200 if treatment == "buflo" else 600
        minimum_interval = 20_000 if treatment == "buflo" else 4_096
        outgoing = capacity.get("outgoing_opportunities")
        incoming = capacity.get("incoming_opportunities")
        common = bool(
            capacity.get("cell_size_bytes") == cell_size
            and capacity.get("minimum_interval_us") == minimum_interval
            and capacity.get("minimum_interval_exercised") is True
            and capacity.get("exact_target_sizes") is True
            and type(outgoing) is int
            and outgoing > 0
            and type(incoming) is int
            and incoming > 0
            and capacity.get("outgoing_full_cells") == outgoing
            and capacity.get("incoming_consumed_bytes") == incoming * cell_size
            and capacity.get("incoming_advertised_bytes") == capacity.get("incoming_consumed_bytes")
            and capacity.get("incoming_terminal_cells") == incoming
            and type(capacity.get("incoming_consumption_delay_us_max")) is int
            and capacity.get("incoming_consumption_delay_us_max") >= 0
            and capacity.get("runner_full_extended_schema_validated") is True
            and re.fullmatch(
                r"[0-9a-f]{64}",
                str(capacity.get("runner_algorithm_evidence_sha256")),
            )
            is not None
            and capacity.get("no_unresolved_credit") is True
        )
        if not common:
            return False
        if treatment == "buflo":
            return _controlled_buflo_terminal_subcell_valid(capacity.get("terminal_subcell"))
        for direction in ("outgoing", "incoming"):
            opportunities = capacity.get(f"{direction}_minimum_interval_opportunities")
            if not (
                type(opportunities) is int
                and opportunities > 0
                and opportunities
                == capacity.get(f"{direction}_minimum_interval_terminal")
                == capacity.get(f"{direction}_minimum_interval_full")
            ):
                return False
        expected_driver_id = {"local-small": 1, "local-large": 4}.get(str(value["workload"]))
        return bool(
            capacity.get("incoming_minimum_interval_local_realized")
            == capacity.get("incoming_minimum_interval_opportunities")
            and capacity.get("incoming_local_realized_cells") == incoming
            and capacity.get("request_rate_driver_resource_id") == expected_driver_id
            and capacity.get("request_rate_driver_boundary_bytes")
            == CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
            and type(capacity.get("request_rate_driver_request_stream_bytes")) is int
            and capacity.get("request_rate_driver_request_stream_bytes")
            >= CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
            and type(capacity.get("request_rate_driver_post_boundary_cells")) is int
            and capacity.get("request_rate_driver_post_boundary_cells")
            >= CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS
        )

    if any(not capacity_is_valid(value) for value in values):
        raise ValueError(
            "controlled clean evidence does not sustain 1200/600-byte client-only "
            "outgoing-cell and incoming-credit opportunities"
        )
    return {
        "schema_version": 1,
        "samples": len(values),
        "profiles": {
            treatment: {
                "samples": sum(value["treatment"] == treatment for value in values),
                "cell_size_bytes": 1_200 if treatment == "buflo" else 600,
                "minimum_interval_us": 20_000 if treatment == "buflo" else 4_096,
                "outgoing_opportunities": sum(
                    int(value["capacity"]["outgoing_opportunities"])
                    for value in values
                    if value["treatment"] == treatment
                ),
                "incoming_opportunities": sum(
                    int(value["capacity"]["incoming_opportunities"])
                    for value in values
                    if value["treatment"] == treatment
                ),
                "incoming_terminal_cells": sum(
                    int(value["capacity"]["incoming_terminal_cells"])
                    for value in values
                    if value["treatment"] == treatment
                ),
                "incoming_consumption_delay_us_max": max(
                    int(value["capacity"]["incoming_consumption_delay_us_max"])
                    for value in values
                    if value["treatment"] == treatment
                ),
                "minimum_interval_exercised_in_every_sample": True,
                "minimum_interval_causal_totals": (
                    {
                        **{
                            f"{direction}_{field}": sum(
                                int(value["capacity"][f"{direction}_minimum_interval_{field}"])
                                for value in values
                                if value["treatment"] == treatment
                            )
                            for direction in ("outgoing", "incoming")
                            for field in ("opportunities", "terminal", "full")
                        },
                        "incoming_local_realized": sum(
                            int(value["capacity"]["incoming_minimum_interval_local_realized"])
                            for value in values
                            if value["treatment"] == treatment
                        ),
                        "incoming_total_local_realized": sum(
                            int(value["capacity"]["incoming_local_realized_cells"])
                            for value in values
                            if value["treatment"] == treatment
                        ),
                    }
                    if treatment != "buflo"
                    else None
                ),
                "terminal_subcell": (
                    _aggregate_controlled_buflo_terminal_subcells(
                        [
                            value["capacity"]["terminal_subcell"]
                            for value in values
                            if value["treatment"] == treatment
                        ]
                    )
                    if treatment == "buflo"
                    else None
                ),
                "no_unresolved_credit": True,
            }
            for treatment in ("buflo", "cs-buflo-ctsp", "cs-buflo-cpsp")
        },
        "passed": True,
    }


def _controlled_buflo_terminal_subcell_valid(value: Any) -> bool:
    return buflo_terminal_state_valid(value)


def _aggregate_controlled_buflo_terminal_subcells(
    values: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not values or any(not _controlled_buflo_terminal_subcell_valid(value) for value in values):
        raise ValueError("controlled BuFLO terminal-subcell evidence is invalid")
    state_versions = {int(value.get("schema_version", 1)) for value in values}
    if len(state_versions) != 1:
        raise ValueError("controlled BuFLO terminal-subcell evidence mixes schema versions")
    state_version = next(iter(state_versions))
    capacities = [int(value["exact_capacity_bytes_cancelled"]) for value in values]
    streams = [int(value["stream_cancellations"]) for value in values]
    latch_times = [int(value["terminal_latched_at_us"]) for value in values]
    post_control_packets = [
        int(value["post_cancellation_unscheduled_defense_control_packets"]) for value in values
    ]
    post_control_bytes = [
        int(value["post_cancellation_unscheduled_defense_control_bytes"]) for value in values
    ]
    schedule_stop = None
    if state_version == 3:
        stops = [value["schedule_stop"] for value in values]
        direction_totals: dict[str, Any] = {}
        for direction in ("outgoing", "incoming"):
            states = [stop["directions"][direction] for stop in stops]
            direction_totals[direction] = {
                **{
                    field: sum(int(state[field]) for state in states)
                    for field in (
                        "scheduled_cells_at_stop",
                        "terminal_cells_at_stop",
                        "drained_cells_after_stop",
                        "terminal_cells_strictly_before_stop",
                        "terminal_cells_at_or_before_stop",
                        "terminal_cells_at_stop_timestamp",
                    )
                },
                "last_scheduled_target_us": {
                    "minimum": min(int(state["last_scheduled_target_us"]) for state in states),
                    "maximum": max(int(state["last_scheduled_target_us"]) for state in states),
                },
                "last_terminal_at_us": {
                    "minimum": min(int(state["last_terminal_at_us"]) for state in states),
                    "maximum": max(int(state["last_terminal_at_us"]) for state in states),
                },
            }
        available = [int(stop["available_bytes"]) for stop in stops]
        stop_times = [int(stop["latched_at_us"]) for stop in stops]
        schedule_stop = {
            "policy": BUFLO_SCHEDULE_STOP_POLICY,
            "terminal_time_semantics": (BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS),
            "latched_samples": sum(stop["latched"] is True for stop in stops),
            "latched_at_us": {
                "minimum": min(stop_times),
                "maximum": max(stop_times),
            },
            "available_bytes": {
                "total": sum(available),
                "minimum": min(available),
                "maximum": max(available),
            },
            "required_bytes": 1_200,
            "samples_with_incoming_drain": sum(
                int(stop["directions"]["incoming"]["drained_cells_after_stop"]) > 0
                for stop in stops
            ),
            "directions": direction_totals,
        }
    return {
        "schema_version": state_version,
        "samples": len(values),
        "terminal_subcell_policy": BUFLO_TERMINAL_SUBCELL_POLICY,
        "terminal_subcell_observer_effect": BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
        "control_evidence_semantics": BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
        "whole_cell_floor_bytes": 1_200,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "terminal_latched_samples": len(values),
        "terminal_latched_at_us": {
            "minimum": min(latch_times),
            "maximum": max(latch_times),
        },
        "samples_with_cancellation": sum(value > 0 for value in streams),
        "stream_cancellations": sum(streams),
        "open_streams_at_latch": sum(int(value["open_streams_at_latch"]) for value in values),
        "receipt_cancellations": sum(int(value["receipt_cancellations"]) for value in values),
        "typed_cancellation_action_events": sum(
            int(value["typed_cancellation_action_events"]) for value in values
        ),
        "pending_request_cancellations": 0,
        "parser_lease_bytes_at_latch": 0,
        "pending_parser_boundaries_at_latch": sum(
            int(value["pending_parser_boundaries_at_latch"]) for value in values
        ),
        **(
            {
                "pending_application_parser_boundaries_at_latch": sum(
                    int(value["pending_application_parser_boundaries_at_latch"]) for value in values
                )
            }
            if state_version in {2, 3}
            else {}
        ),
        **({"schedule_stop": schedule_stop} if state_version == 3 else {}),
        "post_cancellation_unscheduled_defense_control_packets": sum(post_control_packets),
        "post_cancellation_unscheduled_defense_control_bytes": sum(post_control_bytes),
        "exact_capacity_bytes_cancelled": {
            "total": sum(capacities),
            "minimum": min(capacities),
            "maximum": max(capacities),
        },
        "every_residual_below_whole_cell_floor": all(capacity < 1_200 for capacity in capacities),
        "passed": True,
    }


def _ctsp_cpsp_oracle_proof() -> dict[str, Any]:
    from .buflo_reference import csbuflo_padding_target_bytes

    natural_values = (1, 2, 511, 512, 513, 1_000, 1_023, 1_024, 1_025, 16_383, 16_384)
    cover_values = (0, 1, 24, 511, 548, 1_100, 2_048, 16_384)
    vectors = []
    for natural in natural_values:
        for cover in cover_values:
            cpsp = csbuflo_padding_target_bytes(natural, cover, "payload")
            ctsp = csbuflo_padding_target_bytes(natural, cover, "total")
            if ctsp < cpsp:
                raise ValueError("independent CS-BuFLO padding oracle found CTSP below CPSP")
            vectors.append(
                {"natural_bytes": natural, "cover_bytes": cover, "cpsp": cpsp, "ctsp": ctsp}
            )
    return {
        "schema_version": 1,
        "oracle": "qcsd_lab.buflo_reference.csbuflo_padding_target_bytes",
        "proof": (
            "q=ceil_pow2(natural) divides every larger power of two; therefore "
            "ceil((natural+cover)/q)*q <= ceil_pow2(natural+cover)"
        ),
        "vectors_checked": len(vectors),
        "anchors": [
            vector
            for vector in vectors
            if (vector["natural_bytes"], vector["cover_bytes"]) in {(1_000, 24), (1_000, 1_100)}
        ],
        "ctsp_greater_than_or_equal_cpsp": True,
    }


def _validate_ctsp_cpsp_ordering(
    costs: Mapping[tuple[str, str, int], Mapping[str, Mapping[str, int]]],
    *,
    evidence_sha256s: Sequence[str],
    explanation_receipt: Path | None,
) -> dict[str, Any]:
    required = {"cs-buflo-ctsp", "cs-buflo-cpsp"}
    if len(costs) != 40 or any(not required <= set(group) for group in costs.values()):
        raise ValueError("controlled CTSP/CPSP pairing is incomplete")
    pairs = []
    for (netem, workload, visit), group in sorted(costs.items()):
        row = {
            "netem_profile": netem,
            "workload": workload,
            "visit": visit,
            "ctsp": dict(group["cs-buflo-ctsp"]),
            "cpsp": dict(group["cs-buflo-cpsp"]),
        }
        row["ctsp_minus_cpsp_wire_bytes"] = row["ctsp"]["wire_bytes"] - row["cpsp"]["wire_bytes"]
        row["ctsp_minus_cpsp_udp_payload_bytes"] = (
            row["ctsp"]["udp_payload_bytes"] - row["cpsp"]["udp_payload_bytes"]
        )
        pairs.append(row)
    aggregate = {
        treatment: {
            metric: sum(group[treatment][metric] for group in costs.values())
            for metric in ("wire_bytes", "udp_payload_bytes")
        }
        for treatment in required
    }
    aggregate_passed = all(
        aggregate["cs-buflo-ctsp"][metric] >= aggregate["cs-buflo-cpsp"][metric]
        for metric in ("wire_bytes", "udp_payload_bytes")
    )
    contrary_pairs = [
        row
        for row in pairs
        if row["ctsp_minus_cpsp_wire_bytes"] < 0 or row["ctsp_minus_cpsp_udp_payload_bytes"] < 0
    ]
    passed = aggregate_passed and not contrary_pairs
    comparison_binding = {
        "evidence_sha256s": sorted(evidence_sha256s),
        "pairs": pairs,
        "aggregate": aggregate,
    }
    comparison_sha256 = _canonical_digest(comparison_binding)
    explanation = None
    if not passed:
        if explanation_receipt is None:
            raise ValueError(
                "controlled CTSP is below CPSP in an aggregate or paired result without a "
                "reviewed explanation receipt"
            )
        explanation = _validate_ctsp_cpsp_explanation(
            explanation_receipt,
            comparison_sha256=comparison_sha256,
            evidence_sha256s=sorted(evidence_sha256s),
        )
    elif explanation_receipt is not None:
        raise ValueError("CTSP/CPSP explanation was supplied without a contrary controlled result")
    return {
        "schema_version": 1,
        "oracle": _ctsp_cpsp_oracle_proof(),
        "paired_samples": pairs,
        "aggregate": aggregate,
        "contrary_pairs": contrary_pairs,
        "comparison_sha256": comparison_sha256,
        "controlled_ctsp_greater_than_or_equal_cpsp": aggregate_passed,
        "every_controlled_pair_ctsp_greater_than_or_equal_cpsp": not contrary_pairs,
        "reviewed_explanation": explanation,
        "passed": passed or explanation is not None,
    }


def _validate_ctsp_cpsp_explanation(
    path: Path, *, comparison_sha256: str, evidence_sha256s: Sequence[str]
) -> dict[str, Any]:
    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("CTSP/CPSP explanation is not a regular file")
    value = load_json(path)
    required = {
        "schema_version",
        "artifact_type",
        "comparison_sha256",
        "evidence_sha256s",
        "classification",
        "reviewed",
        "reviewer",
        "reason",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-ctsp-cpsp-controlled-explanation"
        or value.get("comparison_sha256") != comparison_sha256
        or value.get("evidence_sha256s") != list(evidence_sha256s)
        or value.get("classification") not in {"expected", "resolved"}
        or value.get("reviewed") is not True
        or not isinstance(value.get("reviewer"), str)
        or not value["reviewer"].strip()
        or not isinstance(value.get("reason"), str)
        or not value["reason"].strip()
    ):
        raise ValueError("CTSP/CPSP reviewed explanation schema or binding is invalid")
    return {"path": str(path), "sha256": sha256_file(path), **value}


def _result_roots_by_declared_name(result_roots: Sequence[Path]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    resolved_roots: set[Path] = set()
    for value in result_roots:
        root = Path(value).resolve()
        if root in resolved_roots:
            raise ValueError("staged capture evidence repeats a result root")
        resolved_roots.add(root)
        experiment_path = root / "experiment.json"
        if experiment_path.is_symlink() or not experiment_path.is_file():
            raise ValueError(f"staged capture result has no regular experiment.json: {root}")
        experiment = load_json(experiment_path)
        name = experiment.get("name") if isinstance(experiment, Mapping) else None
        if not isinstance(name, str) or not name or name in roots:
            raise ValueError("staged capture result identities are missing or duplicated")
        roots[name] = root
    return roots


def _public_campaign_name(stage: str) -> str:
    path = campaign_paths(stage)[0]
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or not isinstance(value.get("name"), str):
        raise TypeError(f"BuFLO {stage} campaign name is invalid")
    return value["name"]


def _experiment_elapsed_seconds(experiment: Mapping[str, Any]) -> float:
    try:
        started = datetime.fromisoformat(str(experiment["started_at"]).replace("Z", "+00:00"))
        completed = datetime.fromisoformat(str(experiment["completed_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as error:
        raise ValueError("study result has invalid acquisition timestamps") from error
    if started.tzinfo is None or completed.tzinfo is None:
        raise ValueError("study acquisition timestamps must include a timezone")
    elapsed = (completed - started).total_seconds()
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError("study result acquisition elapsed time is not positive")
    return elapsed


def _validate_public_stage_result(
    stage: str,
    root: Path,
    *,
    expected_cohort_version: int = 1,
) -> dict[str, Any]:
    if stage not in {"smoke", "rehearsal"}:
        raise ValueError("public prerequisite validation requires smoke or rehearsal")
    from .orchestrator import _redirect_attestation, load_campaign, plan_campaign
    from .verification import verify_result

    version = _cohort_version(expected_cohort_version)
    frozen_admission_path = root / "inputs/capture-admission.json"
    if frozen_admission_path.is_symlink() or not frozen_admission_path.is_file():
        raise ValueError(f"{stage} result does not contain its frozen capture admission")
    frozen_admission = load_json(frozen_admission_path)
    if (
        not isinstance(frozen_admission, Mapping)
        or frozen_admission.get("cohort_version") != version
        or frozen_admission.get("qualification_set") != qualification_set_for_cohort(version)
    ):
        raise ValueError(f"{stage} result cohort version does not match the requested cohort")
    campaign_path = campaign_paths(stage, cohort_version=version)[0]
    campaign = load_campaign(campaign_path)
    verified = verify_result(root)
    experiment = verified.experiment
    expected_samples = load_study_plan()["public_stages"][stage]["expected_samples"]
    if (
        experiment["name"] != campaign.name
        or experiment["purpose"] != campaign.purpose
        or experiment["status"] != "complete"
        or experiment["configuration"].get("campaign_sha256") != sha256_file(campaign_path)
        or len(verified.accepted_samples) != expected_samples
    ):
        raise ValueError(f"{stage} result does not bind the exact checked-in campaign")
    _validate_public_configuration_bindings(experiment["configuration"], campaign)
    _validate_public_result_admission(
        verified.root,
        campaign_path,
        experiment["configuration"],
        expected_source=experiment["source"],
    )
    expected_plan = plan_campaign(campaign)
    observed_plan = experiment["samples"]
    workloads = {workload.id: workload for workload in campaign.workloads}
    identity_fields = (
        "sample_id",
        "workload_id",
        "request_policy",
        "visit",
        "defense",
        "runtime_kind",
        "baseline",
        "seed",
        "path",
    )
    if len(observed_plan) != len(expected_plan):
        raise ValueError(f"{stage} result sample plan has the wrong size")
    for expected, observed in zip(expected_plan, observed_plan, strict=True):
        if any(observed.get(field) != expected[field] for field in identity_fields):
            raise ValueError(f"{stage} result sample plan differs from the frozen campaign")
        diagnostics = observed.get("diagnostics")
        if (
            observed.get("state") != "accepted"
            or observed.get("eligible") is not True
            or not isinstance(diagnostics, Mapping)
            or diagnostics.get("fidelity_eligible") is not True
        ):
            raise ValueError(f"{stage} result is not 100% correctness/fidelity eligible")
        _validate_public_network_condition(diagnostics)
        sample_path = verified.root / observed["path"]
        expected_redirects = _redirect_attestation(
            workloads[observed["workload_id"]],
            sample_path,
        )
        if diagnostics.get("redirect_attestation") != expected_redirects:
            raise ValueError(
                f"{stage} result does not explicitly attest empty prepared/final redirects"
            )
    source = experiment.get("source")
    _validate_clean_source(source, label=f"{stage} result")
    environment = _validate_result_environment(verified, source)
    result_bytes = _verified_result_bytes(verified)
    elapsed_seconds = _experiment_elapsed_seconds(experiment)
    return {
        "root": str(verified.root),
        "name": campaign.name,
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
        "samples": expected_samples,
        "campaign": str(campaign_path),
        "campaign_sha256": sha256_file(campaign_path),
        "evidence_sha256": sha256_file(verified.root / "evidence.sha256"),
        "authoritative_bytes": result_bytes,
        "elapsed_seconds": elapsed_seconds,
        "source": dict(source),
        "environment": environment,
    }


def _validate_public_network_condition(diagnostics: Mapping[str, Any]) -> None:
    value = diagnostics.get("network_condition")
    required = {
        "schema_version",
        "artifact_type",
        "condition",
        "docker_network_mode",
        "interface",
        "applied_netem",
        "qdisc_query_returncode",
        "observed_qdisc",
        "netem_present",
        "capture_offloads_verified",
        "valid",
    }
    offloads = diagnostics.get("offloads")
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-buflo-study-network-condition"
        or value.get("condition") != "public-docker-bridge-no-netem"
        or value.get("docker_network_mode") != "bridge"
        or value.get("interface") != "eth0"
        or value.get("applied_netem") is not False
        or value.get("qdisc_query_returncode") != 0
        or value.get("netem_present") is not False
        or value.get("capture_offloads_verified") is not True
        or value.get("valid") is not True
        or not isinstance(value.get("observed_qdisc"), list)
        or any(
            isinstance(row, Mapping) and row.get("kind") == "netem"
            for row in value["observed_qdisc"]
        )
        or not isinstance(offloads, list)
        or len(offloads) != 1
        or not isinstance(offloads[0], Mapping)
        or offloads[0].get("interface") != "eth0"
        or offloads[0].get("verified") is not True
    ):
        raise ValueError("public result lacks exact no-netem bridge/qdisc/offload evidence")


def _validate_public_configuration_bindings(
    configuration: Mapping[str, Any], campaign: Any
) -> None:
    workload_records = configuration.get("workloads")
    if not isinstance(workload_records, list) or len(workload_records) != len(campaign.workloads):
        raise ValueError("public result workload bindings are invalid")
    for record, workload in zip(workload_records, campaign.workloads, strict=True):
        expected = {
            "id": workload.id,
            "visits": workload.visits,
            "sha256": workload.sha256,
            "resource_count": workload.resource_count,
            "origin_count": workload.origin_count,
            "runtime_manifest_sha256": workload.runtime_sha256,
            "chaff_qualification_sha256": workload.chaff_qualification_sha256,
            "chaff_qualification_scope": workload.chaff_qualification_scope,
            "chaff_prefix_spec_sha256": workload.chaff_prefix_spec_sha256,
            "chaff_manifest_sha256": workload.chaff_manifest_sha256,
        }
        if any(record.get(key) != value for key, value in expected.items() if value is not None):
            raise ValueError("public result workload/chaff hashes differ from current inputs")

    defense_records = configuration.get("defenses")
    if not isinstance(defense_records, list) or len(defense_records) != len(campaign.defenses):
        raise ValueError("public result defense bindings are invalid")
    for record, defense in zip(defense_records, campaign.defenses, strict=True):
        expected = {
            "name": defense.name,
            "kind": defense.kind,
            "baseline": defense.baseline,
            "schedule_sha256": defense.schedule_sha256,
            "parameters_sha256": defense.parameters_sha256,
            "provenance_sha256": defense.parameters_provenance_sha256,
            "input_policy": defense.parameters_input_policy,
        }
        if any(record.get(key) != value for key, value in expected.items() if value is not None):
            raise ValueError("public result defense parameter hashes differ from current inputs")


def _validate_public_result_admission(
    result_root: Path,
    campaign_path: Path,
    configuration: Mapping[str, Any],
    *,
    expected_source: Mapping[str, Any],
) -> None:
    admission_path = result_root / "inputs/capture-admission.json"
    if (
        admission_path.is_symlink()
        or not admission_path.is_file()
        or configuration.get("capture_admission_sha256") != sha256_file(admission_path)
    ):
        raise ValueError("public result does not bind its frozen capture admission")
    admission = validate_capture_admission(admission_path)
    allowed = [
        row
        for row in admission["allowed_campaigns"]
        if row["campaign_sha256"] == sha256_file(campaign_path)
        and Path(row["result_root"]) == result_root.resolve()
    ]
    if (
        admission["source"] != expected_source
        or admission["stage"] not in {"smoke", "rehearsal"}
        or len(allowed) != 1
    ):
        raise ValueError("public result is not authorized by its typed capture admission")


def _validate_clean_source(value: Any, *, label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != SOURCE_METADATA_KEYS:
        raise ValueError(f"{label} source metadata is malformed")
    image = value["image_digest"]
    commits = (value["lab_commit"], value["neqo_commit"], value["neqo_pinned_commit"])
    if (
        not isinstance(image, str)
        or not image.startswith("sha256:")
        or len(image) != 71
        or any(character not in "0123456789abcdef" for character in image[7:])
        or any(
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
            for commit in commits
        )
        or value["neqo_commit"] != value["neqo_pinned_commit"]
        or value["lab_dirty"] is not False
        or value["neqo_dirty"] is not False
        or value["lab_patch_sha256"] != EMPTY_SHA256
        or value["neqo_patch_sha256"] != EMPTY_SHA256
    ):
        raise ValueError(f"{label} was not produced by one concrete clean collection image")


def _expected_clean_collection_source(
    expected_source: Mapping[str, Any] | None,
    *,
    label: str,
) -> dict[str, Any]:
    """Select the ambient source, or one foundation-bound collection source.

    The private override exists only so a prepare-role process can reconstruct
    collection evidence before the foundation validator separately proves that
    the ambient process is the prepare image from the same no-cache build.
    """

    selected = source_metadata() if expected_source is None else expected_source
    _validate_clean_source(selected, label=label)
    return dict(selected)


def _require_one_current_clean_source(
    values: Sequence[Mapping[str, Any]],
    *,
    expected_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not values:
        raise ValueError("staged capture evidence has no source lineage")
    first = dict(values[0])
    _validate_clean_source(first, label="staged capture evidence")
    if any(dict(value) != first for value in values[1:]):
        raise ValueError("staged capture cohorts were not produced by one exact image/source")
    current = _expected_clean_collection_source(
        expected_source,
        label="current collection image",
    )
    if current != first:
        raise ValueError("staged capture evidence does not match the current collection image")
    return first


def _verified_result_bytes(verified: Any) -> int:
    return (verified.root / "evidence.sha256").stat().st_size + sum(
        (verified.root / relative).stat().st_size for relative in verified.checksums
    )


def _validate_result_environment(verified: Any, source: Mapping[str, Any]) -> dict[str, Any]:
    path = verified.root / "inputs/study-environment.json"
    configuration = verified.experiment.get("configuration")
    if (
        path.is_symlink()
        or not path.is_file()
        or not isinstance(configuration, Mapping)
        or configuration.get("study_environment_sha256") != sha256_file(path)
    ):
        raise ValueError("study result does not bind its sealed Docker environment receipt")
    return validate_study_environment_receipt(
        load_json(path),
        expected_image_digest=source["image_digest"],
    )


def run_study_action(
    action: str,
    *,
    stage: str | None = None,
    block: int | None = None,
    result_roots: Sequence[Path] = (),
    controlled_result_roots: Sequence[Path] = (),
    regression_result_roots: Sequence[Path] = (),
    formal_result_roots: Sequence[Path] = (),
    smoke_result_root: Path | None = None,
    rehearsal_result_root: Path | None = None,
    handoff: Path | None = None,
    destination: Path | None = None,
    formal: bool = False,
    bootstrap_draws: int = 10_000,
    dlsvm_available_wall_seconds: float | None = None,
    external_sources: Mapping[str, Path] | None = None,
    reference_root: Path | None = None,
    reference_receipt: Path | None = None,
    qualification_receipt: Path | None = None,
    capture_admission: Path | None = None,
    formal_cohort_manifest: Path | None = None,
    historical_pre_snapshot: Path | None = None,
    historical_post_snapshot: Path | None = None,
    evaluation_receipt: Path | None = None,
    comparison_review: Path | None = None,
    code_gate_receipt: Path | None = None,
    attestation: Path | None = None,
    snapshot_phase: str | None = None,
    cohort_id: str | None = None,
    cohort_version: int = 1,
    formal_window_hours: float | None = None,
    local_netem_profile: str | None = None,
    network_name: str | None = None,
    server_one_qdisc_b64: str | None = None,
    server_two_qdisc_b64: str | None = None,
    controlled_network_evidence_b64: str | None = None,
) -> StudyActionResult:
    """Execute one explicit study boundary while retaining candidate status."""

    if action not in {
        "reference",
        "qualify",
        "historical-snapshot",
        "freeze-cohort",
        "code-gate",
        "capture",
        "export",
        "evaluate",
        "verify",
    }:
        raise ValueError("unsupported BuFLO study action")
    version = _cohort_version(cohort_version)
    plan = load_study_plan()
    details: dict[str, Any] = {
        "study_plan": {"path": str(STUDY_PLAN), "sha256": sha256_file(STUDY_PLAN)},
        "cohort_version": version,
        "qualification_set": qualification_set_for_cohort(version),
    }
    blockers: list[str] = []
    if formal or (action == "capture" and stage in {None, "formal"}):
        details["historical_corpus_guard"] = validate_historical_corpus_guard(plan, deep=True)
    if action in {
        "reference",
        "qualify",
        "historical-snapshot",
        "freeze-cohort",
        "code-gate",
        "capture",
        "verify",
    }:
        details["references"] = list(validate_references(external_sources))
        details["parameters"] = list(validate_parameters())
        details["established_seven_baseline"] = validate_established_seven_baseline()
        details["campaign_matrix"] = validate_campaign_matrix(
            stage,
            cohort_version=version,
        )
    if action == "reference":
        source_gate: Path | Mapping[str, Path] | None = reference_root or external_sources
        supplied_sources = set(external_sources or {})
        if reference_root is None:
            missing_sources = sorted(REQUIRED_REFERENCE_SOURCES - supplied_sources)
            if missing_sources:
                blockers.append(
                    "reference source/archive inputs are missing: " + ", ".join(missing_sources)
                )
        if destination is None:
            blockers.append("reference conformance requires an absent receipt destination")
        if os.environ.get("QCSD_REFERENCE_ISOLATED") != "1":
            blockers.append(
                "reference conformance must run through the network-isolated reference image"
            )
        if not blockers:
            assert source_gate is not None and destination is not None
            from .buflo_reference import run_reference_gate

            destination = destination.absolute()
            if destination.exists() or destination.is_symlink():
                raise FileExistsError(f"reference execution receipt already exists: {destination}")
            reference_source = source_metadata()
            _validate_clean_source(reference_source, label="reference execution")
            build_receipt = validate_build_execution_receipt(
                build_execution_receipt_path(version),
                expected_cohort_version=version,
            )
            build_binding = {
                "path": build_receipt["path"],
                "sha256": build_receipt["sha256"],
            }
            build_value = load_json(Path(build_binding["path"]))
            build = _validate_build_execution_value(
                build_value,
                expected_cohort_version=version,
            )
            if build["images"]["reference"]["id"] != reference_source["image_digest"]:
                raise ValueError("reference image differs from the no-cache build receipt")
            started_wall = datetime.now(timezone.utc)
            started_monotonic = time.monotonic()
            isolation = _reference_runtime_isolation()
            with tempfile.TemporaryDirectory(
                dir=destination.parent,
                prefix=".qcsd-reference-execution-",
            ) as temporary:
                inner = Path(temporary) / "conformance.json"
                gate = run_reference_gate(source_gate, inner)
                canonical = _validate_canonical_reference_receipt(gate.receipt_path)
                if canonical["sha256"] != CONFORMANCE_RECEIPT_SHA256:
                    raise ValueError("executed reference gate differs from the canonical oracle")
            finished_wall = datetime.now(timezone.utc)
            elapsed = time.monotonic() - started_monotonic
            receipt_value = _reference_execution_value(
                source=reference_source,
                build_execution={
                    "sha256": build_binding["sha256"],
                    "receipt": build_value,
                    "completion_path": (
                        f"/lab/artifacts/buflo-study/"
                        f"build-completion-v{version}.json"
                    ),
                    "completion_sha256": build_receipt["completion_sha256"],
                    "completion_payload_sha256": build_receipt[
                        "completion_payload_sha256"
                    ],
                    "completion": build_receipt["build_completion"],
                },
                isolation=isolation,
                execution_id=secrets.token_hex(16),
                started_at=started_wall.isoformat(),
                finished_at=finished_wall.isoformat(),
                duration_seconds=elapsed,
            )
            output = _create_only_json(destination, receipt_value)
            details["reference_execution"] = validate_reference_gate_receipt(
                output,
                expected_cohort_version=version,
            )
        return StudyActionResult(
            action,
            "pass" if not blockers else "blocked",
            "candidate",
            details,
            tuple(blockers),
        )
    if action == "historical-snapshot":
        if destination is None or snapshot_phase not in {"pre-formal", "post-formal"}:
            raise ValueError("historical snapshot requires --destination and --snapshot-phase")
        output = create_historical_guard_snapshot(
            destination,
            phase=snapshot_phase,
            formal_result_roots=result_roots,
            pre_snapshot=historical_pre_snapshot,
            cohort_version=version,
        )
        details["historical_snapshot"] = _file_binding(output)
        return StudyActionResult(action, "created", "candidate", details)
    if action == "freeze-cohort":
        if destination is None or cohort_id is None or historical_pre_snapshot is None:
            raise ValueError(
                "formal cohort freeze requires destination, cohort ID, and pre-formal snapshot"
            )
        output = create_formal_cohort_manifest(
            destination,
            cohort_id=cohort_id,
            results_root=LAB_ROOT / "results",
            historical_pre_snapshot=historical_pre_snapshot,
            cohort_version=version,
        )
        details["formal_cohort"] = _file_binding(output)
        return StudyActionResult(action, "created", "candidate", details)
    if action == "code-gate":
        if destination is None or not result_roots:
            raise ValueError("code gate requires destination and exact regression result roots")
        output = create_code_gate_receipt(
            destination,
            regression_result_roots=result_roots,
            cohort_version=version,
        )
        details["code_gate"] = _file_binding(output)
        return StudyActionResult(action, "created", "candidate", details)
    if action == "qualify":
        controlled_evidence = controlled_result_roots or result_roots
        if os.environ.get("QCSD_BUFLO_QUALIFY_CONTROLLED_ONLY") == "1":
            if not controlled_evidence:
                raise ValueError("controlled-only qualification requires controlled roots")
            details["controlled_results"] = validate_controlled_results(controlled_evidence)
            return StudyActionResult(action, "pass", "candidate", details)
        ready, qualification = qualification_status(
            controlled_evidence,
            cohort_version=version,
        )
        details["qualification"] = qualification
        if controlled_evidence:
            details["controlled_results"] = validate_controlled_results(controlled_evidence)
        if ready and destination is not None:
            output = create_qualification_receipt(
                destination,
                controlled_evidence,
                cohort_version=version,
            )
            details["qualification_receipt"] = _file_binding(output)
        details["command"] = (
            "./qcsd-lab qualify-response-chaff --set "
            + qualification_set_for_cohort(version)
            + " "
            + " ".join(WORKLOADS)
        )
        if not ready:
            blockers.append(qualification)
        return StudyActionResult(
            action,
            "pass" if ready else "blocked",
            "candidate",
            details,
            tuple(blockers),
        )
    if action == "capture":
        if stage == "controlled" and local_netem_profile is not None:
            if (
                destination is None
                or not network_name
                or not controlled_network_evidence_b64
                or server_one_qdisc_b64 is not None
                or server_two_qdisc_b64 is not None
            ):
                raise ValueError(
                    "internal controlled capture requires destination and shared-router evidence"
                )
            result = execute_local_controlled_profile(
                destination,
                netem_profile=local_netem_profile,
                network=network_name,
                controlled_network_evidence_b64=controlled_network_evidence_b64,
                cohort_version=version,
            )
            details["result"] = str(result)
            details["resume_contract"] = (
                "controlled-results.json selects one immutable experiment.json result per "
                "netem profile; accepted samples are never rewritten"
            )
            return StudyActionResult(action, "complete", "candidate", details)
        if stage == "regression" and local_netem_profile is not None:
            if (
                local_netem_profile != "clean"
                or destination is None
                or not network_name
                or not controlled_network_evidence_b64
                or server_one_qdisc_b64 is not None
                or server_two_qdisc_b64 is not None
            ):
                raise ValueError(
                    "internal regression capture requires clean shared-router Docker evidence"
                )
            results = execute_local_regression(
                destination,
                network=network_name,
                controlled_network_evidence_b64=controlled_network_evidence_b64,
                cohort_version=version,
            )
            details["results"] = [str(result) for result in results]
            details["regression"] = validate_regression_results(results)
            return StudyActionResult(action, "complete", "candidate", details)
        admitted: dict[str, Any] | None = None
        if stage in {"controlled", "regression"}:
            ready, qualification = qualification_status(
                controlled_result_roots,
                require_controlled=stage != "controlled",
                cohort_version=version,
            )
        elif capture_admission is not None:
            if destination is not None:
                raise ValueError("capture accepts either an existing admission or a destination")
            admitted = validate_capture_admission(
                capture_admission,
                expected_cohort_version=version,
            )
            if admitted["stage"] != stage:
                raise ValueError("capture admission stage does not match requested stage")
            if admitted["cohort_version"] != version:
                raise ValueError("capture admission cohort version does not match the request")
            if reference_receipt is not None and _file_binding(reference_receipt) != {
                "path": admitted["reference_gate"]["path"],
                "sha256": admitted["reference_gate"]["sha256"],
            }:
                raise ValueError("supplied reference receipt differs from the frozen admission")
            if qualification_receipt is not None and _file_binding(qualification_receipt) != {
                "path": admitted["qualification"]["path"],
                "sha256": admitted["qualification"]["sha256"],
            }:
                raise ValueError("supplied qualification receipt differs from the frozen admission")
            frozen_code_gate = admitted.get("code_gate")
            if code_gate_receipt is not None and _file_binding(code_gate_receipt) != (
                {"path": frozen_code_gate["path"], "sha256": frozen_code_gate["sha256"]}
                if isinstance(frozen_code_gate, Mapping)
                else None
            ):
                raise ValueError("supplied code-gate receipt differs from the frozen admission")
            if result_roots:
                supplied_staged = validate_staged_capture_prerequisites(
                    stage,
                    result_roots,
                    expected_cohort_version=version,
                )
                if supplied_staged != admitted["staged_prerequisites"]:
                    raise ValueError(
                        "supplied prerequisite results differ from the frozen admission"
                    )
            for supplied, key, label in (
                (formal_cohort_manifest, "formal_cohort", "formal cohort"),
                (
                    historical_pre_snapshot,
                    "historical_pre_formal_snapshot",
                    "historical snapshot",
                ),
            ):
                frozen = admitted.get(key)
                if supplied is not None and _file_binding(supplied) != frozen:
                    raise ValueError(f"supplied {label} differs from the frozen admission")
            if (
                formal_window_hours is not None
                and isinstance(admitted.get("formal_capacity"), Mapping)
                and float(formal_window_hours)
                != admitted["formal_capacity"]["available_window_hours"]
            ):
                raise ValueError("supplied formal window differs from the frozen admission")
            ready = True
            qualification = (
                f"{admitted['qualification']['path']}; frozen sustained chaff/capacity verified"
            )
            details["qualification_receipt"] = admitted["qualification"]
            details["reference_gate"] = admitted["reference_gate"]
            if admitted.get("code_gate") is not None:
                details["code_gate"] = admitted["code_gate"]
            details["staged_prerequisites"] = admitted["staged_prerequisites"]
            if admitted["formal_capacity"] is not None:
                details["formal_capacity"] = admitted["formal_capacity"]
        elif qualification_receipt is None:
            ready = False
            qualification = "public capture requires a typed qualification receipt"
        else:
            qualified = validate_qualification_receipt(
                qualification_receipt,
                expected_cohort_version=version,
            )
            ready = True
            qualification = f"{qualified['path']}; sustained chaff/capacity verified"
            details["qualification_receipt"] = qualified
        if not ready:
            blockers.append(qualification)
        if stage in {"controlled", "regression"}:
            details["generated_matrix"] = validate_campaign_matrix(
                stage,
                cohort_version=version,
            )
            blockers.append(
                "local controlled/regression capture must be launched through ./qcsd-lab so "
                "Docker can provision both server and client network shapers"
            )
            return StudyActionResult(action, "blocked", "candidate", details, tuple(blockers))
        if stage not in STAGED_CAPTURE_PREREQUISITES:
            raise ValueError("public capture requires smoke, rehearsal, or formal stage")
        if admitted is None and reference_receipt is None:
            blockers.append(
                "public capture requires --reference-receipt from the isolated conformance gate"
            )
        elif admitted is None:
            details["reference_gate"] = validate_reference_gate_receipt(
                reference_receipt,
                expected_cohort_version=version,
            )
        if admitted is None and not result_roots:
            blockers.append(
                f"{stage} capture requires exact prior result roots: "
                + ", ".join(STAGED_CAPTURE_PREREQUISITES[stage])
            )
        elif admitted is None:
            details["staged_prerequisites"] = validate_staged_capture_prerequisites(
                stage,
                result_roots,
                expected_cohort_version=version,
            )
        if stage == "formal" and admitted is None:
            if version >= FORMAL_FAIL_CLOSED_COHORT_VERSION and code_gate_receipt is None:
                blockers.append("formal capture requires --code-gate-receipt")
            if "staged_prerequisites" in details:
                try:
                    details["formal_capacity"] = validate_formal_capture_capacity(
                        details["staged_prerequisites"],
                        available_window_hours=formal_window_hours,
                    )
                except ValueError as error:
                    blockers.append(str(error))
            elif formal_window_hours is None:
                blockers.append(
                    "formal capture requires --formal-window-hours of at least "
                    f"{FORMAL_MINIMUM_AVAILABLE_HOURS:g}"
                )
        selected = campaign_paths(
            stage,
            block,
            cohort_version=version,
            create_resolved=admitted is None,
        )
        details["campaigns"] = [str(path) for path in selected]
        details["commands"] = [f"./qcsd-lab run {path}" for path in selected]
        details["resume_contract"] = (
            "resume only with ./qcsd-lab resume RESULT; experiment.json is authoritative"
        )
        if not blockers:
            from .orchestrator import preflight_campaign

            for path in selected:
                preflight_campaign(path)
        if not blockers:
            if capture_admission is None:
                if destination is None or qualification_receipt is None:
                    raise ValueError(
                        "public capture requires an absent admission destination and qualification receipt"
                    )
                capture_admission = create_capture_admission(
                    destination,
                    stage=stage,
                    reference_receipt=reference_receipt,
                    qualification_receipt=qualification_receipt,
                    prerequisite_result_roots=result_roots,
                    results_root=LAB_ROOT / "results",
                    formal_cohort_manifest=formal_cohort_manifest,
                    historical_pre_snapshot=historical_pre_snapshot,
                    code_gate_receipt=(code_gate_receipt if stage == "formal" else None),
                    formal_window_hours=formal_window_hours,
                    cohort_version=version,
                )
            admitted = validate_capture_admission(
                capture_admission,
                expected_cohort_version=version,
            )
            if admitted["stage"] != stage:
                raise ValueError("capture admission stage does not match requested stage")
            if admitted["cohort_version"] != version:
                raise ValueError(
                    "capture admission cohort version does not match requested version"
                )
            details["capture_admission"] = _file_binding(capture_admission)
            if stage == "formal" and not any(
                Path(row["result_root"]).exists() for row in admitted["allowed_campaigns"]
            ):
                capacity = admitted.get("formal_capacity")
                if not isinstance(capacity, Mapping):
                    raise ValueError("formal capture admission has no frozen capacity estimate")
                _report_frozen_formal_prelaunch(capacity)
            from .orchestrator import (
                _study_capture_lock,
                resume_campaign,
                run_campaign,
            )

            results_root = LAB_ROOT / "results"
            captured = []
            lock_context = (
                nullcontext()
                if os.environ.get("QCSD_BUFLO_CAPTURE_LOCK_HELD") == "1"
                else _study_capture_lock(results_root)
            )
            with lock_context:
                old_lock = os.environ.get("QCSD_BUFLO_CAPTURE_LOCK_HELD")
                old_admission = os.environ.get("QCSD_BUFLO_CAPTURE_ADMISSION")
                old_network_condition = os.environ.get("QCSD_STUDY_NETWORK_CONDITION")
                os.environ["QCSD_BUFLO_CAPTURE_LOCK_HELD"] = "1"
                os.environ["QCSD_BUFLO_CAPTURE_ADMISSION"] = str(capture_admission)
                os.environ["QCSD_STUDY_NETWORK_CONDITION"] = "public-docker-bridge-no-netem"
                try:
                    for path in selected:
                        root = admitted_result_root(
                            capture_admission,
                            path,
                            require_sequence=True,
                        )
                        if root.exists():
                            captured.append(resume_campaign(root))
                        else:
                            captured.append(run_campaign(path, results_root))
                finally:
                    if old_lock is None:
                        os.environ.pop("QCSD_BUFLO_CAPTURE_LOCK_HELD", None)
                    else:
                        os.environ["QCSD_BUFLO_CAPTURE_LOCK_HELD"] = old_lock
                    if old_admission is None:
                        os.environ.pop("QCSD_BUFLO_CAPTURE_ADMISSION", None)
                    else:
                        os.environ["QCSD_BUFLO_CAPTURE_ADMISSION"] = old_admission
                    if old_network_condition is None:
                        os.environ.pop("QCSD_STUDY_NETWORK_CONDITION", None)
                    else:
                        os.environ["QCSD_STUDY_NETWORK_CONDITION"] = old_network_condition
            details["captured_results"] = [str(path) for path in captured]
            return StudyActionResult(action, "complete", "candidate", details)
        return StudyActionResult(
            action,
            "ready" if not blockers else "blocked",
            "candidate",
            details,
            tuple(blockers),
        )
    if action == "export":
        if not result_roots or destination is None:
            raise ValueError("study export requires result roots and an absent destination")
        from .buflo_handoff import export_study_handoff

        output = export_study_handoff(result_roots, destination, formal=formal)
        details["handoff"] = str(output)
        return StudyActionResult(action, "created", "candidate", details)
    if action == "evaluate":
        if handoff is None or destination is None:
            raise ValueError("study evaluation requires a handoff and absent destination")
        from .buflo_evaluation import evaluate_handoff

        output = evaluate_handoff(
            handoff,
            destination,
            formal=formal,
            bootstrap_draws=bootstrap_draws,
            dlsvm_available_wall_seconds=dlsvm_available_wall_seconds,
        )
        details["evaluation_receipt"] = str(output)
        return StudyActionResult(action, "created", "candidate", details)
    if action == "verify":
        if attestation is not None:
            if destination is not None:
                raise ValueError("verify accepts an attestation or a create-only destination")
            verified_attestation = validate_validation_attestation(
                attestation,
                expected_cohort_version=version,
                dlsvm_available_wall_seconds=dlsvm_available_wall_seconds,
            )
            details["validation_attestation"] = verified_attestation
            return StudyActionResult(
                action,
                "pass",
                VALIDATED_STATUS,
                details,
            )
        required_inputs = {
            "destination": destination,
            "reference receipt": reference_receipt,
            "code-gate receipt": code_gate_receipt,
            "qualification receipt": qualification_receipt,
            "smoke result": smoke_result_root,
            "rehearsal result": rehearsal_result_root,
            "capture admission": capture_admission,
            "formal cohort": formal_cohort_manifest,
            "handoff": handoff,
            "evaluation receipt": evaluation_receipt,
            "comparison review": comparison_review,
            "historical pre-formal snapshot": historical_pre_snapshot,
            "historical post-formal snapshot": historical_post_snapshot,
        }
        missing = [label for label, value in required_inputs.items() if value is None]
        if not regression_result_roots:
            missing.append("regression result roots")
        if not controlled_result_roots:
            missing.append("controlled result roots")
        if not formal_result_roots:
            missing.append("formal result roots")
        if missing:
            blockers.append("typed validation attestation requires: " + ", ".join(missing))
            details["hard_gates"] = plan["hard_gates"]
            return StudyActionResult(
                action,
                "blocked",
                "candidate",
                details,
                tuple(blockers),
            )
        assert all(value is not None for value in required_inputs.values())
        validate_qualification_receipt(
            qualification_receipt,
            controlled_result_roots=controlled_result_roots,
            expected_cohort_version=version,
        )
        output = create_validation_attestation(
            destination,
            reference_receipt=reference_receipt,
            code_gate_receipt=code_gate_receipt,
            qualification_receipt=qualification_receipt,
            regression_result_roots=regression_result_roots,
            controlled_result_roots=controlled_result_roots,
            smoke_result_root=smoke_result_root,
            rehearsal_result_root=rehearsal_result_root,
            formal_result_roots=formal_result_roots,
            capture_admission=capture_admission,
            formal_cohort_manifest=formal_cohort_manifest,
            handoff=handoff,
            evaluation_receipt=evaluation_receipt,
            comparison_review=comparison_review,
            historical_pre_snapshot=historical_pre_snapshot,
            historical_post_snapshot=historical_post_snapshot,
            dlsvm_available_wall_seconds=dlsvm_available_wall_seconds,
        )
        details["validation_attestation"] = _created_validation_attestation_result(output)
        return StudyActionResult(action, "created", VALIDATED_STATUS, details)
    if handoff is not None:
        from .buflo_handoff import validate_study_handoff

        details["handoff"] = str(validate_study_handoff(handoff, formal=formal, deep=True))
    if result_roots:
        from .verification import verify_result

        details["results"] = [verify_result(path).as_dict() for path in result_roots]
    ready, qualification = qualification_status(controlled_result_roots)
    if not ready:
        blockers.append(qualification)
    blockers.append("all twelve capture/evaluation gates have not been attested")
    details["hard_gates"] = plan["hard_gates"]
    return StudyActionResult(action, "candidate", "candidate", details, tuple(blockers))


def _validate_formal_performance_evidence(evaluation: Mapping[str, Any]) -> dict[str, Any]:
    performance = evaluation.get("performance_breakdowns")
    algorithm = evaluation.get("algorithm_breakdowns")
    paired = evaluation.get("paired_per_visit")
    summary = evaluation.get("paired_metrics")
    if (
        not isinstance(performance, Mapping)
        or not isinstance(algorithm, Mapping)
        or algorithm.get("available") is not True
        or algorithm.get("classifier_input") is not False
        or set(algorithm)
        != {
            "schema_version",
            "available",
            "classifier_input",
            "strata",
            "buflo_terminal_tail_strata",
            "buflo_schedule_stop_strata",
            "cs_buflo_local_termination_strata",
        }
        or algorithm.get("schema_version") != 3
        or not isinstance(paired, list)
        or len(paired) != 1_000
        or not isinstance(summary, Mapping)
        or set(summary) != {"buflo", "cs-buflo"}
        or any(summary[mode].get("pairs") != 500 for mode in summary)
    ):
        raise ValueError("formal evaluation performance/algorithm evidence is incomplete")
    expected_lengths = {
        "directional": 300,
        "client": 150,
        "paired_directional_by_workload_block": 200,
        "paired_client_by_workload_block": 100,
        "paired_mode_direction_block_workload_bootstrap_95": 4,
        "paired_mode_client_block_workload_bootstrap_95": 2,
    }
    if set(performance) != set(expected_lengths) or any(
        not isinstance(performance[key], list) or len(performance[key]) != count
        for key, count in expected_lengths.items()
    ):
        raise ValueError("formal performance stratum inventory is not exact")

    def require_axes(
        rows: Sequence[Mapping[str, Any]],
        *,
        fields: tuple[str, ...],
        expected: set[tuple[Any, ...]],
        count_field: str,
        count: int,
        label: str,
    ) -> None:
        seen: set[tuple[Any, ...]] = set()
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError(f"formal {label} stratum is invalid")
            key = tuple(row.get(field) for field in fields)
            if key not in expected or key in seen or row.get(count_field) != count:
                raise ValueError(f"formal {label} stratum identity is invalid")
            seen.add(key)
        if seen != expected:
            raise ValueError(f"formal {label} stratum coverage is incomplete")

    defenses = ("undefended", "buflo", "cs-buflo")
    defended = ("buflo", "cs-buflo")
    require_axes(
        performance["directional"],
        fields=("defense", "workload_id", "acquisition_block_index", "direction"),
        expected={
            (mode, workload, block, direction)
            for mode in defenses
            for workload in WORKLOADS
            for block in range(10)
            for direction in ("outgoing", "incoming")
        },
        count_field="samples",
        count=10,
        label="directional performance",
    )
    require_axes(
        performance["client"],
        fields=("defense", "workload_id", "acquisition_block_index"),
        expected={
            (mode, workload, block)
            for mode in defenses
            for workload in WORKLOADS
            for block in range(10)
        },
        count_field="samples",
        count=10,
        label="client performance",
    )
    require_axes(
        performance["paired_directional_by_workload_block"],
        fields=("defense", "workload_id", "acquisition_block_index", "direction"),
        expected={
            (mode, workload, block, direction)
            for mode in defended
            for workload in WORKLOADS
            for block in range(10)
            for direction in ("outgoing", "incoming")
        },
        count_field="pairs",
        count=10,
        label="paired directional performance",
    )
    require_axes(
        performance["paired_client_by_workload_block"],
        fields=("defense", "workload_id", "acquisition_block_index"),
        expected={
            (mode, workload, block)
            for mode in defended
            for workload in WORKLOADS
            for block in range(10)
        },
        count_field="pairs",
        count=10,
        label="paired client performance",
    )
    require_axes(
        performance["paired_mode_direction_block_workload_bootstrap_95"],
        fields=("defense", "direction"),
        expected={(mode, direction) for mode in defended for direction in ("outgoing", "incoming")},
        count_field="pairs",
        count=500,
        label="mode-direction performance",
    )
    require_axes(
        performance["paired_mode_client_block_workload_bootstrap_95"],
        fields=("defense",),
        expected={(mode,) for mode in defended},
        count_field="pairs",
        count=500,
        label="mode-client performance",
    )
    required_costs = {
        "user_cpu_seconds",
        "system_cpu_seconds",
        "wall_time_seconds",
        "maximum_rss_bytes",
        "voluntary_context_switches",
        "involuntary_context_switches",
        "timer_wakeups",
        "transport_retransmissions",
    }
    for row in performance["paired_mode_client_block_workload_bootstrap_95"]:
        costs = row.get("paired_client_costs") if isinstance(row, Mapping) else None
        if (
            not isinstance(costs, Mapping)
            or not required_costs <= set(costs)
            or any(costs[metric].get("available") is not True for metric in required_costs)
            or not all(
                key in row
                for key in (
                    "completion_ratio_block_workload_bootstrap_95",
                    "added_seconds_block_workload_bootstrap_95",
                    "goodput_ratio_block_workload_bootstrap_95",
                )
            )
        ):
            raise ValueError("formal paired client cost distributions/CIs are incomplete")
    if not isinstance(algorithm.get("strata"), list) or len(algorithm["strata"]) != 300:
        raise ValueError("formal algorithm diagnostic stratum inventory is not exact")
    expected_algorithm_strata = {
        (defense, workload, block, direction)
        for defense in ("undefended", "buflo", "cs-buflo")
        for workload in WORKLOADS
        for block in range(10)
        for direction in ("outgoing", "incoming")
    }
    observed_algorithm_strata: set[tuple[str, str, int, str]] = set()
    for row in algorithm["strata"]:
        if not isinstance(row, Mapping):
            raise ValueError("formal algorithm diagnostic stratum is invalid")
        key = (
            row.get("defense"),
            row.get("workload_id"),
            row.get("acquisition_block_index"),
            row.get("direction"),
        )
        if (
            key not in expected_algorithm_strata
            or key in observed_algorithm_strata
            or row.get("samples") != 10
        ):
            raise ValueError("formal algorithm diagnostic stratum identity is invalid")
        observed_algorithm_strata.add(key)
    if observed_algorithm_strata != expected_algorithm_strata:
        raise ValueError("formal algorithm diagnostic stratum coverage is incomplete")
    cs_local_et_rows = algorithm.get("cs_buflo_local_termination_strata")
    cs_local_et_keys = {
        "defense",
        "workload_id",
        "acquisition_block_index",
        "samples",
        "before_application_complete_samples",
        "latched_at_us",
        "pending_request_cancellations",
        "stream_cancellations",
        "application_receive_streams_handed_off",
        "application_parser_boundaries_handed_off",
        "application_parser_lease_bytes_handed_off",
        "application_send_endpoints_released",
        "post_local_et_natural_outgoing_bytes",
        "post_local_et_natural_incoming_bytes",
    }
    expected_cs_local_et_strata = {
        (workload, block) for workload in WORKLOADS for block in range(10)
    }
    seen_cs_local_et_strata: set[tuple[str, int]] = set()
    if not isinstance(cs_local_et_rows, list) or len(cs_local_et_rows) != 50:
        raise ValueError("formal CS-BuFLO local-termination stratum inventory is not exact")
    for row in cs_local_et_rows:
        if not isinstance(row, Mapping) or set(row) != cs_local_et_keys:
            raise ValueError("formal CS-BuFLO local-termination stratum schema is not exact")
        workload = row.get("workload_id")
        block = row.get("acquisition_block_index")
        key = (workload, block)
        if (
            row.get("defense") != "cs-buflo"
            or key not in expected_cs_local_et_strata
            or key in seen_cs_local_et_strata
            or row.get("samples") != 10
        ):
            raise ValueError("formal CS-BuFLO local-termination stratum identity is invalid")
        seen_cs_local_et_strata.add(key)
        integer_fields = {
            field: row.get(field)
            for field in cs_local_et_keys
            - {
                "defense",
                "workload_id",
                "acquisition_block_index",
                "samples",
                "latched_at_us",
            }
        }
        before = integer_fields["before_application_complete_samples"]
        handoff_total = sum(
            integer_fields[field]
            for field in (
                "application_receive_streams_handed_off",
                "application_parser_boundaries_handed_off",
                "application_parser_lease_bytes_handed_off",
                "application_send_endpoints_released",
            )
        )
        post_total = sum(
            integer_fields[field]
            for field in (
                "post_local_et_natural_outgoing_bytes",
                "post_local_et_natural_incoming_bytes",
            )
        )
        latch = row.get("latched_at_us")
        if (
            any(type(value) is not int or value < 0 for value in integer_fields.values())
            or not 0 <= before <= 10
            or integer_fields["pending_request_cancellations"] != 0
            or (before == 0 and (handoff_total != 0 or post_total != 0))
            or (before > 0 and handoff_total == 0)
            or not isinstance(latch, Mapping)
            or set(latch) != {"p50", "p90", "p95"}
            or any(
                not isinstance(latch[field], (int, float))
                or isinstance(latch[field], bool)
                or not math.isfinite(float(latch[field]))
                or float(latch[field]) <= 0
                for field in ("p50", "p90", "p95")
            )
            or not latch["p50"] <= latch["p90"] <= latch["p95"]
        ):
            raise ValueError("formal CS-BuFLO local-termination evidence is invalid")
    if seen_cs_local_et_strata != expected_cs_local_et_strata:
        raise ValueError("formal CS-BuFLO local-termination coverage is incomplete")
    tail_rows = algorithm.get("buflo_terminal_tail_strata")
    tail_keys = {
        "defense",
        "workload_id",
        "acquisition_block_index",
        "samples",
        "samples_with_cancellation",
        "terminal_subcell_policy",
        "terminal_subcell_observer_effect",
        "control_evidence_semantics",
        "stream_cancellations",
        "receipt_cancellations",
        "typed_cancellation_action_events",
        "pending_request_cancellations",
        "open_streams_at_latch",
        "parser_lease_bytes_at_latch",
        "pending_parser_boundaries_at_latch",
        "pending_application_parser_boundaries_at_latch",
        "exact_capacity_bytes_cancelled",
        "terminal_latched_at_us",
        "post_cancellation_unscheduled_defense_control_packets",
        "post_cancellation_unscheduled_defense_control_bytes",
    }
    expected_tail_strata = {(workload, block) for workload in WORKLOADS for block in range(10)}
    seen_tail_strata: set[tuple[str, int]] = set()
    total_tail_samples = 0
    total_tail_cancellations = 0
    if not isinstance(tail_rows, list) or len(tail_rows) != 50:
        raise ValueError("formal BuFLO terminal-tail stratum inventory is not exact")
    for row in tail_rows:
        if not isinstance(row, Mapping) or set(row) != tail_keys:
            raise ValueError("formal BuFLO terminal-tail stratum schema is not exact")
        workload = row.get("workload_id")
        block = row.get("acquisition_block_index")
        key = (workload, block)
        if (
            row.get("defense") != "buflo"
            or workload not in WORKLOADS
            or type(block) is not int
            or not 0 <= block < 10
            or key in seen_tail_strata
            or row.get("samples") != 10
            or row.get("terminal_subcell_policy") != [BUFLO_TERMINAL_SUBCELL_POLICY]
            or row.get("terminal_subcell_observer_effect")
            != [BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT]
            or row.get("control_evidence_semantics") != [BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS]
        ):
            raise ValueError("formal BuFLO terminal-tail stratum identity is invalid")
        seen_tail_strata.add(key)
        integer_fields = {
            field: row.get(field)
            for field in (
                "samples_with_cancellation",
                "stream_cancellations",
                "receipt_cancellations",
                "typed_cancellation_action_events",
                "pending_request_cancellations",
                "open_streams_at_latch",
                "parser_lease_bytes_at_latch",
                "pending_parser_boundaries_at_latch",
                "pending_application_parser_boundaries_at_latch",
                "post_cancellation_unscheduled_defense_control_packets",
                "post_cancellation_unscheduled_defense_control_bytes",
            )
        }
        if any(type(value) is not int or value < 0 for value in integer_fields.values()):
            raise ValueError("formal BuFLO terminal-tail counters are invalid")
        samples_with_cancellation = integer_fields["samples_with_cancellation"]
        streams = integer_fields["stream_cancellations"]
        control_packets = integer_fields["post_cancellation_unscheduled_defense_control_packets"]
        control_bytes = integer_fields["post_cancellation_unscheduled_defense_control_bytes"]
        capacity = row.get("exact_capacity_bytes_cancelled")
        latch = row.get("terminal_latched_at_us")
        if (
            not 0 <= samples_with_cancellation <= 10
            or (samples_with_cancellation == 0) != (streams == 0)
            or streams < samples_with_cancellation
            or streams != integer_fields["receipt_cancellations"]
            or streams != integer_fields["typed_cancellation_action_events"]
            or streams != integer_fields["open_streams_at_latch"]
            or integer_fields["pending_request_cancellations"] != 0
            or integer_fields["parser_lease_bytes_at_latch"] != 0
            or integer_fields["pending_application_parser_boundaries_at_latch"] != 0
            or integer_fields["pending_parser_boundaries_at_latch"] > streams
            or (streams == 0 and integer_fields["pending_parser_boundaries_at_latch"] != 0)
            or (streams == 0 and (control_packets != 0 or control_bytes != 0))
            or (streams > 0 and (control_packets == 0 or control_bytes == 0))
            or control_packets < samples_with_cancellation
            or control_bytes < control_packets
            or not isinstance(capacity, Mapping)
            or set(capacity) != {"total", "minimum", "maximum", "p50", "p90", "p95"}
            or any(
                type(capacity[field]) is not int or capacity[field] < 0
                for field in ("total", "minimum", "maximum")
            )
            or not 0 <= capacity["minimum"] <= capacity["maximum"] < 1_200
            or not capacity["minimum"] * 10 <= capacity["total"] <= capacity["maximum"] * 10
            or (
                streams == 0
                and any(
                    float(capacity[field]) != 0.0
                    for field in (
                        "total",
                        "minimum",
                        "maximum",
                        "p50",
                        "p90",
                        "p95",
                    )
                )
            )
            or any(
                not isinstance(capacity[field], (int, float))
                or isinstance(capacity[field], bool)
                or not math.isfinite(float(capacity[field]))
                or not capacity["minimum"] <= float(capacity[field]) <= capacity["maximum"]
                for field in ("p50", "p90", "p95")
            )
            or not capacity["p50"] <= capacity["p90"] <= capacity["p95"]
            or not isinstance(latch, Mapping)
            or set(latch) != {"p50", "p90", "p95"}
            or any(
                not isinstance(latch[field], (int, float))
                or isinstance(latch[field], bool)
                or not math.isfinite(float(latch[field]))
                or float(latch[field]) < 10_000_000
                for field in ("p50", "p90", "p95")
            )
            or not latch["p50"] <= latch["p90"] <= latch["p95"]
        ):
            raise ValueError("formal BuFLO terminal-tail stratum evidence is invalid")
        total_tail_samples += int(row["samples"])
        total_tail_cancellations += streams
    if seen_tail_strata != expected_tail_strata or total_tail_samples != 500:
        raise ValueError("formal BuFLO terminal-tail coverage is incomplete")

    schedule_stop_rows = algorithm.get("buflo_schedule_stop_strata")
    schedule_stop_keys = {
        "defense",
        "workload_id",
        "acquisition_block_index",
        "samples",
        "policy",
        "terminal_time_semantics",
        "latched_samples",
        "latched_at_us",
        "available_bytes",
        "required_bytes",
        "samples_with_incoming_drain",
        "directions",
    }
    direction_keys = {
        "scheduled_cells_at_stop",
        "terminal_cells_at_stop",
        "drained_cells_after_stop",
        "last_scheduled_target_us",
        "last_terminal_at_us",
        "terminal_cells_strictly_before_stop",
        "terminal_cells_at_or_before_stop",
        "terminal_cells_at_stop_timestamp",
    }
    time_summary_keys = {"minimum", "maximum", "p50", "p90", "p95"}

    def valid_time_summary(value: Any, *, minimum: int = 0) -> bool:
        return bool(
            isinstance(value, Mapping)
            and set(value) == time_summary_keys
            and all(
                isinstance(value[field], (int, float))
                and not isinstance(value[field], bool)
                and math.isfinite(float(value[field]))
                and float(value[field]) >= minimum
                for field in time_summary_keys
            )
            and value["minimum"] <= value["p50"] <= value["p90"] <= value["p95"]
            and value["p95"] <= value["maximum"]
        )

    seen_schedule_stop_strata: set[tuple[str, int]] = set()
    total_schedule_stop_samples = 0
    total_incoming_drained_cells = 0
    if not isinstance(schedule_stop_rows, list) or len(schedule_stop_rows) != 50:
        raise ValueError("formal BuFLO schedule-stop stratum inventory is not exact")
    for row in schedule_stop_rows:
        if not isinstance(row, Mapping) or set(row) != schedule_stop_keys:
            raise ValueError("formal BuFLO schedule-stop stratum schema is not exact")
        workload = row.get("workload_id")
        block = row.get("acquisition_block_index")
        key = (workload, block)
        stop_times = row.get("latched_at_us")
        available = row.get("available_bytes")
        directions = row.get("directions")
        if (
            row.get("defense") != "buflo"
            or key not in expected_tail_strata
            or key in seen_schedule_stop_strata
            or row.get("samples") != 10
            or row.get("policy") != [BUFLO_SCHEDULE_STOP_POLICY]
            or row.get("terminal_time_semantics") != [BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS]
            or row.get("latched_samples") != 10
            or row.get("required_bytes") != [1_200]
            or type(row.get("samples_with_incoming_drain")) is not int
            or not 0 <= row["samples_with_incoming_drain"] <= 10
            or not valid_time_summary(stop_times, minimum=10_000_000)
            or not isinstance(available, Mapping)
            or set(available) != {"total", *time_summary_keys}
            or type(available.get("total")) is not int
            or not 0 <= available["total"] <= 11_990
            or not valid_time_summary({field: available[field] for field in time_summary_keys})
            or available["maximum"] >= 1_200
            or not available["minimum"] * 10 <= available["total"] <= available["maximum"] * 10
            or not isinstance(directions, Mapping)
            or set(directions) != {"outgoing", "incoming"}
        ):
            raise ValueError("formal BuFLO schedule-stop stratum identity is invalid")
        seen_schedule_stop_strata.add(key)
        for direction in ("outgoing", "incoming"):
            state = directions[direction]
            if not isinstance(state, Mapping) or set(state) != direction_keys:
                raise ValueError("formal BuFLO schedule-stop direction schema is not exact")
            integers = {
                field: state.get(field)
                for field in direction_keys - {"last_scheduled_target_us", "last_terminal_at_us"}
            }
            scheduled = integers["scheduled_cells_at_stop"]
            terminal = integers["terminal_cells_at_stop"]
            drained = integers["drained_cells_after_stop"]
            strictly_before = integers["terminal_cells_strictly_before_stop"]
            at_or_before = integers["terminal_cells_at_or_before_stop"]
            at_timestamp = integers["terminal_cells_at_stop_timestamp"]
            if (
                any(type(value) is not int or value < 0 for value in integers.values())
                or scheduled == 0
                or terminal + drained != scheduled
                or not 0 <= strictly_before <= terminal <= at_or_before <= scheduled
                or at_timestamp != at_or_before - strictly_before
                or (direction == "outgoing" and drained != 0)
                or not valid_time_summary(state.get("last_scheduled_target_us"))
                or not valid_time_summary(state.get("last_terminal_at_us"))
                or state["last_scheduled_target_us"]["maximum"] > stop_times["maximum"]
            ):
                raise ValueError("formal BuFLO schedule-stop direction evidence is invalid")
        outgoing = directions["outgoing"]
        incoming = directions["incoming"]
        incoming_drained = incoming["drained_cells_after_stop"]
        if (
            outgoing["scheduled_cells_at_stop"] != incoming["scheduled_cells_at_stop"]
            or outgoing["last_scheduled_target_us"] != incoming["last_scheduled_target_us"]
            or (row["samples_with_incoming_drain"] == 0) != (incoming_drained == 0)
            or incoming_drained < row["samples_with_incoming_drain"]
        ):
            raise ValueError("formal BuFLO schedule-stop cross-direction evidence is invalid")
        total_schedule_stop_samples += int(row["samples"])
        total_incoming_drained_cells += int(incoming_drained)
    if seen_schedule_stop_strata != expected_tail_strata or total_schedule_stop_samples != 500:
        raise ValueError("formal BuFLO schedule-stop coverage is incomplete")
    return {
        "paired_visits": len(paired),
        "performance_strata": dict(expected_lengths),
        "algorithm_strata": len(algorithm["strata"]),
        "buflo_terminal_tail_strata": len(tail_rows),
        "buflo_terminal_tail_samples": total_tail_samples,
        "buflo_terminal_tail_cancellations": total_tail_cancellations,
        "buflo_schedule_stop_strata": len(schedule_stop_rows),
        "buflo_schedule_stop_samples": total_schedule_stop_samples,
        "buflo_schedule_stop_incoming_drained_cells": total_incoming_drained_cells,
        "cs_buflo_local_termination_strata": len(cs_local_et_rows),
        "paired_client_metrics": sorted(required_costs),
        "passed": True,
    }


def _hard_gate_identity_sha256(ordinal: int, gate: str) -> str:
    return _canonical_digest({"ordinal": ordinal, "gate": gate})


def _hard_gate_records(
    evidence_sha256s: Sequence[str], *, schema_version: int
) -> list[dict[str, Any]]:
    records = []
    for ordinal, gate in enumerate(HARD_GATE_IDENTITIES, start=1):
        record: dict[str, Any] = {
            "gate": gate,
            "result": "pass",
            "evidence_sha256s": list(evidence_sha256s),
        }
        if schema_version >= 2:
            record["gate_identity_sha256"] = _hard_gate_identity_sha256(ordinal, gate)
        records.append(record)
    return records


def _validate_attestation_hard_gates(value: Any, *, schema_version: int) -> None:
    if not isinstance(value, list) or len(value) != len(HARD_GATE_IDENTITIES):
        raise ValueError("validation attestation hard-gate inventory is incomplete")
    required = {"gate", "result", "evidence_sha256s"}
    if schema_version >= 2:
        required.add("gate_identity_sha256")
    for ordinal, (record, gate) in enumerate(
        zip(value, HARD_GATE_IDENTITIES, strict=True), start=1
    ):
        evidence = record.get("evidence_sha256s") if isinstance(record, Mapping) else None
        if (
            not isinstance(record, Mapping)
            or set(record) != required
            or record.get("gate") != gate
            or record.get("result") != "pass"
            or not isinstance(evidence, list)
            or not evidence
            or evidence != sorted(set(evidence))
            or any(
                not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in evidence
            )
            or (
                schema_version >= 2
                and record.get("gate_identity_sha256") != _hard_gate_identity_sha256(ordinal, gate)
            )
        ):
            raise ValueError(
                f"validation attestation hard-gate identity is invalid: ordinal {ordinal}"
            )


def _validation_attestation_value(
    *,
    reference_receipt: Path,
    code_gate_receipt: Path,
    qualification_receipt: Path,
    regression_result_roots: Sequence[Path],
    controlled_result_roots: Sequence[Path],
    smoke_result_root: Path,
    rehearsal_result_root: Path,
    formal_result_roots: Sequence[Path],
    capture_admission: Path,
    formal_cohort_manifest: Path,
    handoff: Path,
    evaluation_receipt: Path,
    comparison_review: Path,
    historical_pre_snapshot: Path,
    historical_post_snapshot: Path,
    deep_code_gate: bool,
    dlsvm_available_wall_seconds: float | None = None,
) -> dict[str, Any]:
    from .buflo_evaluation import validate_evaluation_receipt
    from .buflo_handoff import _validate_source_results, validate_study_handoff
    from .verification import verify_result

    load_study_plan()
    qualification = validate_qualification_receipt(
        qualification_receipt,
        controlled_result_roots=controlled_result_roots,
    )
    cohort_version = qualification["cohort_version"]
    reference = validate_reference_gate_receipt(
        reference_receipt,
        expected_cohort_version=cohort_version,
    )
    regression = validate_regression_results(regression_result_roots)
    code = validate_code_gate_receipt(
        code_gate_receipt,
        regression_result_roots=regression_result_roots,
        expected_cohort_version=cohort_version,
        deep=deep_code_gate,
    )
    controlled = qualification["controlled_results"]
    if controlled.get("samples") != 160:
        raise ValueError("validation attestation controlled cohort is incomplete")
    smoke = _validate_public_stage_result(
        "smoke",
        smoke_result_root,
        expected_cohort_version=cohort_version,
    )
    rehearsal = _validate_public_stage_result(
        "rehearsal",
        rehearsal_result_root,
        expected_cohort_version=cohort_version,
    )
    if len(formal_result_roots) != 10:
        raise ValueError("validation attestation requires ten formal result roots")
    verified_formal = tuple(verify_result(Path(root)) for root in formal_result_roots)
    _validate_source_results(verified_formal, formal=True)
    cohort = validate_formal_cohort_manifest(formal_cohort_manifest)
    admission = validate_capture_admission(capture_admission)
    expected_formal_roots = [Path(row["result_root"]) for row in cohort["formal_campaigns"]]
    if (
        admission.get("stage") != "formal"
        or admission.get("cohort_version") != cohort_version
        or cohort.get("cohort_version") != cohort_version
        or smoke.get("cohort_version") != cohort_version
        or rehearsal.get("cohort_version") != cohort_version
        or admission.get("formal_cohort") != _file_binding(formal_cohort_manifest)
        or (
            cohort_version >= FORMAL_FAIL_CLOSED_COHORT_VERSION
            and admission.get("code_gate") != code
        )
        or expected_formal_roots != [receipt.root for receipt in verified_formal]
        or [Path(row["result_root"]) for row in admission["allowed_campaigns"]]
        != expected_formal_roots
    ):
        raise ValueError("validation attestation formal admission/cohort selection is invalid")
    handoff_root = validate_study_handoff(handoff, formal=True, deep=True)
    dataset = load_json(handoff_root / "dataset.json")
    if [Path(block["result_root"]) for block in dataset["blocks"]] != expected_formal_roots:
        raise ValueError("formal handoff blocks differ from the prospective cohort roots")
    evaluation = validate_evaluation_receipt(
        evaluation_receipt,
        handoff_root=handoff_root,
        formal=True,
        deep=True,
        dlsvm_available_wall_seconds=dlsvm_available_wall_seconds,
    )
    if cohort_version >= FORMAL_FAIL_CLOSED_COHORT_VERSION and (
        cohort.get("formal_evaluation") != FORMAL_BOOTSTRAP_CONTRACT
        or evaluation.get("bootstrap_draws") != FORMAL_BOOTSTRAP_DRAWS
    ):
        raise ValueError(
            "validation attestation formal evaluation differs from the prospective bootstrap contract"
        )
    performance = _validate_formal_performance_evidence(evaluation)
    comparison = _validate_comparison_review_value(
        comparison_review,
        evaluation_receipt=evaluation_receipt,
        handoff_root=handoff_root,
        evaluation=evaluation,
        formal=True,
    )
    historical_pre = validate_historical_guard_snapshot(
        historical_pre_snapshot,
        phase="pre-formal",
        expected_cohort_version=cohort_version,
    )
    historical_post = validate_historical_guard_snapshot(
        historical_post_snapshot,
        phase="post-formal",
        formal_result_roots=formal_result_roots,
        pre_snapshot=historical_pre_snapshot,
        expected_cohort_version=cohort_version,
    )
    if (
        historical_pre["historical_corpus_guard_sha256"]
        != historical_post["historical_corpus_guard_sha256"]
        or cohort["historical_pre_formal_snapshot"] != _file_binding(historical_pre_snapshot)
        or admission["historical_pre_formal_snapshot"] != _file_binding(historical_pre_snapshot)
    ):
        raise ValueError("validation attestation historical before/after binding is invalid")
    source = regression["source"]
    source_values = (
        code["source"],
        qualification["source"],
        smoke["source"],
        rehearsal["source"],
        cohort["source"],
        admission["source"],
        historical_pre["source"],
        historical_post["source"],
        dataset["execution_source"],
        dataset["exporter_source"],
    )
    if any(value != source for value in source_values):
        raise ValueError("validation attestation evidence does not share one image/source")
    formal_environments = [
        _validate_result_environment(receipt, source) for receipt in verified_formal
    ]
    build_execution = _one_build_execution_identity(
        [
            *(record["environment"] for record in regression["results"]),
            *(record["environment"] for record in controlled["results"]),
            smoke["environment"],
            rehearsal["environment"],
            *formal_environments,
        ]
    )
    build_receipt = validate_build_execution_receipt(
        build_execution_receipt_path(cohort_version),
        expected_collection_image=source["image_digest"],
        expected_cohort_version=cohort_version,
    )
    expected_build_execution = _current_build_execution_identity(build_receipt)
    if (
        build_execution != expected_build_execution
        or reference.get("build_execution") != build_execution
        or admission.get("build_execution") != build_execution
        or qualification.get("build_execution")
        != {"path": build_receipt["path"], "sha256": build_receipt["sha256"]}
        or code.get("build_execution_receipt")
        != {"path": build_receipt["path"], "sha256": build_receipt["sha256"]}
        or cohort.get("build_execution_receipt")
        != {"path": build_receipt["path"], "sha256": build_receipt["sha256"]}
        or historical_pre.get("build_execution_receipt")
        != {"path": build_receipt["path"], "sha256": build_receipt["sha256"]}
        or historical_post.get("build_execution_receipt")
        != {"path": build_receipt["path"], "sha256": build_receipt["sha256"]}
        or admission.get("build_execution_receipt")
        != {"path": build_receipt["path"], "sha256": build_receipt["sha256"]}
    ):
        raise ValueError("validation evidence does not bind one current no-cache build")
    evidence = {
        "build_execution": {
            "path": build_receipt["path"],
            "sha256": build_receipt["sha256"],
        },
        "reference_receipt": _file_binding(reference_receipt),
        "code_gate_receipt": _file_binding(code_gate_receipt),
        "qualification_receipt": _file_binding(qualification_receipt),
        "regression_results": [_result_binding(path) for path in regression_result_roots],
        "controlled_results": [_result_binding(path) for path in controlled_result_roots],
        "smoke_result": _result_binding(smoke_result_root),
        "rehearsal_result": _result_binding(rehearsal_result_root),
        "formal_results": [_result_binding(path) for path in formal_result_roots],
        "capture_admission": _file_binding(capture_admission),
        "formal_cohort": _file_binding(formal_cohort_manifest),
        "handoff": {
            "root": str(handoff_root),
            "sha256sums_sha256": sha256_file(handoff_root / "SHA256SUMS"),
            "dataset_sha256": sha256_file(handoff_root / "dataset.json"),
            "samples_sha256": sha256_file(handoff_root / "samples.jsonl"),
        },
        "evaluation_receipt": _file_binding(evaluation_receipt),
        "comparison_review": _file_binding(comparison_review),
        "historical_pre_snapshot": _file_binding(historical_pre_snapshot),
        "historical_post_snapshot": _file_binding(historical_post_snapshot),
    }
    evidence_digests = sorted(
        {
            binding["sha256"]
            for key, binding in evidence.items()
            if isinstance(binding, Mapping) and "sha256" in binding
        }
        | {
            binding["evidence_sha256"]
            for key in ("regression_results", "controlled_results", "formal_results")
            for binding in evidence[key]
        }
        | {
            evidence["smoke_result"]["evidence_sha256"],
            evidence["rehearsal_result"]["evidence_sha256"],
            evidence["handoff"]["sha256sums_sha256"],
        }
    )
    attestation_schema_version = 2 if cohort_version >= FORMAL_FAIL_CLOSED_COHORT_VERSION else 1
    hard_gates = _hard_gate_records(evidence_digests, schema_version=attestation_schema_version)
    return {
        "schema_version": attestation_schema_version,
        "artifact_type": ATTESTATION_ARTIFACT_TYPE,
        "study_id": BUFLO_STUDY_ID,
        "cohort_version": cohort_version,
        "qualification_set": qualification_set_for_cohort(cohort_version),
        "study_plan": _file_binding(STUDY_PLAN),
        "implementation_status": VALIDATED_STATUS,
        "implementation_status_description": VALIDATED_STATUS_DESCRIPTION,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "no_waivers": True,
        "source": source,
        "evidence": evidence,
        "validation_summary": {
            "cohort_version": cohort_version,
            "reference_profiles_checked": reference["profiles_checked"],
            "no_cache_build_execution": build_execution,
            "code_gate_commands": len(code["lab_commands"])
            + len(code["rust_code_gate"]["commands"]),
            "regression_samples": regression["samples"],
            "controlled_samples": controlled["samples"],
            "controlled_capacity_sha256": _canonical_digest(controlled["sustained_cell_capacity"]),
            "ctsp_cpsp_ordering_sha256": _canonical_digest(controlled["ctsp_cpsp_ordering"]),
            "smoke_samples": smoke["samples"],
            "rehearsal_samples": rehearsal["samples"],
            "formal_samples": evaluation["sample_count"],
            "formal_temporal_acquisition": dataset["temporal_acquisition"],
            "performance": performance,
            "comparison_review": comparison,
            "historical_guard_sha256": historical_post["historical_corpus_guard_sha256"],
        },
        "hard_gates": hard_gates,
        "all_hard_gates_passed": True,
    }


def create_validation_attestation(
    destination: Path,
    **inputs: Any,
) -> Path:
    """Emit promotion authority only after independently rerunning every hard gate."""

    protected: list[Path] = [LAB_ROOT / "handoffs/classifier-multiorigin5-v2"]
    for key in (
        "regression_result_roots",
        "controlled_result_roots",
        "formal_result_roots",
    ):
        protected.extend(Path(path) for path in inputs.get(key, ()))
    for key in (
        "smoke_result_root",
        "rehearsal_result_root",
        "handoff",
        "evaluation_receipt",
        "historical_pre_snapshot",
        "historical_post_snapshot",
    ):
        if inputs.get(key) is not None:
            protected.append(Path(inputs[key]))
    destination = require_disjoint_path(
        destination,
        tuple(protected),
        label="validation attestation destination",
    )
    value = _validation_attestation_value(**inputs, deep_code_gate=True)
    output = _create_only_json(destination, value)
    expected_bytes = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if output.read_bytes() != expected_bytes or load_json(output) != value:
        raise RuntimeError("created validation attestation differs from its validated value")
    return output


def _created_validation_attestation_result(path: Path) -> dict[str, Any]:
    """Return a freshly created attestation without rerunning its expensive hard gates."""

    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    if not isinstance(value, Mapping):
        raise RuntimeError("created validation attestation is not an object")
    return {"path": binding["path"], "sha256": binding["sha256"], **value}


def validate_validation_attestation(
    path: Path,
    *,
    expected_cohort_version: int | None = None,
    deep_code_gate: bool = True,
    dlsvm_available_wall_seconds: float | None = None,
) -> dict[str, Any]:
    """Independently reconstruct a typed all-pass promotion attestation."""

    binding = _file_binding(path)
    value = load_json(Path(binding["path"]))
    if not isinstance(value, Mapping):
        raise ValueError("validation attestation is not an object")
    evidence = value.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("validation attestation typed evidence is missing")
    stored_version = _cohort_version(value.get("cohort_version"))
    if expected_cohort_version is not None and stored_version != _cohort_version(
        expected_cohort_version
    ):
        raise ValueError("validation attestation cohort version differs from the request")
    expected_schema_version = 2 if stored_version >= FORMAL_FAIL_CLOSED_COHORT_VERSION else 1
    if (
        value.get("schema_version") != expected_schema_version
        or value.get("artifact_type") != ATTESTATION_ARTIFACT_TYPE
        or value.get("study_id") != BUFLO_STUDY_ID
        or value.get("implementation_status") != VALIDATED_STATUS
        or value.get("implementation_status_description") != VALIDATED_STATUS_DESCRIPTION
        or value.get("implementation_scope") != "client_only_quic"
        or value.get("paper_equivalent") is not False
        or value.get("no_waivers") is not True
        or value.get("all_hard_gates_passed") is not True
    ):
        raise ValueError("validation attestation promotion envelope is invalid")
    _validate_attestation_hard_gates(
        value.get("hard_gates"), schema_version=expected_schema_version
    )

    def file_path(key: str) -> Path:
        item = evidence.get(key)
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise ValueError(f"validation attestation evidence is missing: {key}")
        return Path(item["path"])

    def result_paths(key: str) -> tuple[Path, ...]:
        items = evidence.get(key)
        if not isinstance(items, list) or any(
            not isinstance(item, Mapping) or not isinstance(item.get("root"), str) for item in items
        ):
            raise ValueError(f"validation attestation result evidence is missing: {key}")
        return tuple(Path(item["root"]) for item in items)

    smoke = evidence.get("smoke_result")
    rehearsal = evidence.get("rehearsal_result")
    handoff = evidence.get("handoff")
    if not all(
        isinstance(item, Mapping) and isinstance(item.get("root"), str)
        for item in (smoke, rehearsal, handoff)
    ):
        raise ValueError("validation attestation public/handoff roots are missing")
    expected = _validation_attestation_value(
        reference_receipt=file_path("reference_receipt"),
        code_gate_receipt=file_path("code_gate_receipt"),
        qualification_receipt=file_path("qualification_receipt"),
        regression_result_roots=result_paths("regression_results"),
        controlled_result_roots=result_paths("controlled_results"),
        smoke_result_root=Path(smoke["root"]),
        rehearsal_result_root=Path(rehearsal["root"]),
        formal_result_roots=result_paths("formal_results"),
        capture_admission=file_path("capture_admission"),
        formal_cohort_manifest=file_path("formal_cohort"),
        handoff=Path(handoff["root"]),
        evaluation_receipt=file_path("evaluation_receipt"),
        comparison_review=file_path("comparison_review"),
        historical_pre_snapshot=file_path("historical_pre_snapshot"),
        historical_post_snapshot=file_path("historical_post_snapshot"),
        deep_code_gate=deep_code_gate,
        dlsvm_available_wall_seconds=dlsvm_available_wall_seconds,
    )
    if value != expected:
        raise ValueError("validation attestation differs from independently derived hard gates")
    return {"path": binding["path"], "sha256": binding["sha256"], **expected}


def _validate_evidence_bindings(values: Any) -> None:
    if not isinstance(values, list) or not values:
        raise ValueError("validation evidence bindings must be non-empty")
    for value in values:
        if not isinstance(value, dict) or not {"path", "sha256"} <= set(value):
            raise ValueError("validation evidence binding is malformed")
        path = Path(value["path"])
        if path.is_symlink() or not path.is_file() or sha256_file(path) != value["sha256"]:
            raise ValueError(f"validation evidence binding is invalid: {path}")


def canonical_json(value: Mapping[str, Any]) -> str:
    """Stable presentation helper used by the CLI and tests."""

    return json.dumps(value, indent=2, sort_keys=True) + "\n"
