"""Clean-room offline references for BuFLO and CS-BuFLO.

This module is deliberately independent of the live defense runtime.  It
turns the algorithms and result tables in the primary papers into small,
deterministic oracles that can qualify a future runtime implementation.  No
source from either authors' implementation is reproduced here.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .util import LAB_ROOT, load_json, sha256_file

REFERENCE_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 1
BUFLO_REFERENCE_ID = "buflo-ieee-sp-2012-v1"
CSBUFLO_REFERENCE_ID = "csbuflo-wpes-2014-v1"
BUFLO_REFERENCE_FILENAME = f"{BUFLO_REFERENCE_ID}.json"
CSBUFLO_REFERENCE_FILENAME = f"{CSBUFLO_REFERENCE_ID}.json"

BUFLO_HEADER_BYTES = 52
CSBUFLO_QUIET_TIME_US = 2_000_000
CSBUFLO_MAX_RATE_SAMPLES = 1_000
MAX_REFERENCE_TEXT_BYTES = 16 * 1024 * 1024
_SOURCE_DIRECTIONS = ("incoming", "outgoing")
_LIVE_DIRECTIONS = ("outgoing", "incoming")
_DIRECTION_SET = frozenset(_LIVE_DIRECTIONS)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_OVERHEAD_LINE_RE = re.compile(
    r"^(?P<record>.+):\s*(?P<defended>[0-9]+),\s*(?P<baseline>[0-9]+),\s*"
    r"(?P<ratio>(?:[0-9]+(?:\.[0-9]+)?)|inf)$"
)
_CSBUFLO_RATE_QUANTIZATION_DISCREPANCY = {
    "classification": "known-internal-paper-prose-vs-algorithm-conflict",
    "paper_algorithm_location": "Algorithm-2-lines-382-and-395-396",
    "paper_algorithm_rule": "2**floor(log2(median-eligible-interval))",
    "paper_prose_location": "WPES-2014-lines-450-455",
    "paper_prose_rule": "round-up-rho-to-a-power-of-two",
    "resolution_basis": "algorithm-pseudocode-and-formula-control-the-independent-oracle",
    "resolved_rule": "2**floor(log2(upper-integer-median-interval))",
}


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        qualifier = "positive " if positive else "non-negative "
        raise ValueError(f"{label} must be a {qualifier}integer")
    return value


@dataclass(frozen=True, slots=True)
class BufloProfile:
    """One of Dyer et al.'s eight published BuFLO parameter tuples."""

    tau_ms: int
    rho_ms: int
    packet_size_bytes: int
    header_bytes: int = BUFLO_HEADER_BYTES

    def __post_init__(self) -> None:
        _uint(self.tau_ms, "BuFLO tau")
        _uint(self.rho_ms, "BuFLO rho", positive=True)
        _uint(self.packet_size_bytes, "BuFLO packet size", positive=True)
        _uint(self.header_bytes, "BuFLO header size")
        if self.header_bytes >= self.packet_size_bytes:
            raise ValueError("BuFLO header must be smaller than the fixed packet")

    @property
    def payload_capacity_bytes(self) -> int:
        return self.packet_size_bytes - self.header_bytes

    @property
    def key(self) -> str:
        return f"tau-{self.tau_ms}-rho-{self.rho_ms}-d-{self.packet_size_bytes}"


BUFLO_PROFILES = (
    BufloProfile(0, 40, 1_000),
    BufloProfile(0, 40, 1_500),
    BufloProfile(0, 20, 1_000),
    BufloProfile(0, 20, 1_500),
    BufloProfile(10_000, 40, 1_000),
    BufloProfile(10_000, 40, 1_500),
    BufloProfile(10_000, 20, 1_000),
    BufloProfile(10_000, 20, 1_500),
)
BUFLO_PROFILE_BY_KEY = {profile.key: profile for profile in BUFLO_PROFILES}


class BufloDirectionOrder(str, Enum):
    """Same-timestamp order for a bidirectional offline projection."""

    LIVE_OUTGOING_FIRST = "live-outgoing-first"
    SOURCE_INCOMING_FIRST = "source-incoming-first"


@dataclass(frozen=True, slots=True)
class BufloSourcePacket:
    """One packet in the timestamped SSH trace consumed by the paper simulator."""

    monotonic_ms: int
    direction: str
    length_bytes: int

    def __post_init__(self) -> None:
        _uint(self.monotonic_ms, "source timestamp")
        if self.direction not in _DIRECTION_SET:
            raise ValueError(f"source direction must be one of {_LIVE_DIRECTIONS}")
        _uint(self.length_bytes, "source packet length", positive=True)


@dataclass(frozen=True, slots=True)
class BufloEmission:
    """One fixed-size packet emitted by the clean-room offline transformer."""

    monotonic_ms: int
    direction: str
    length_bytes: int
    real_payload_bytes: int
    dummy_payload_bytes: int

    @property
    def payload_bytes(self) -> int:
        return self.real_payload_bytes + self.dummy_payload_bytes


def transform_buflo(
    packets: Iterable[BufloSourcePacket],
    profile: BufloProfile,
    *,
    direction_order: BufloDirectionOrder | str = BufloDirectionOrder.LIVE_OUTGOING_FIRST,
) -> tuple[BufloEmission, ...]:
    """Apply the paper's ideal bidirectional BuFLO transform.

    The observation-layer compatibility profile follows the primary paper's
    52-byte IPv4/TCP header model: input packets contribute ``length - 52``
    real bytes, pure ACKs contribute none, and every output length includes
    that header model.  The first tick is zero and the minimum-duration test
    is inclusive, matching the author's deterministic trace transformer.
    """

    if not isinstance(profile, BufloProfile):
        raise TypeError("profile must be a BufloProfile")
    try:
        resolved_order = BufloDirectionOrder(direction_order)
    except (TypeError, ValueError) as error:
        raise ValueError("unknown BuFLO direction order") from error
    directions = (
        _SOURCE_DIRECTIONS
        if resolved_order is BufloDirectionOrder.SOURCE_INCOMING_FIRST
        else _LIVE_DIRECTIONS
    )
    supplied = tuple(packets)
    previous_time = -1
    for packet in supplied:
        if not isinstance(packet, BufloSourcePacket):
            raise TypeError("packets must contain BufloSourcePacket values")
        if packet.monotonic_ms < previous_time:
            raise ValueError("BuFLO source packets must be chronological")
        if packet.length_bytes < profile.header_bytes:
            raise ValueError("source packet is smaller than the reference header model")
        previous_time = packet.monotonic_ms
    # The pinned Trace.addPacket discards pure 52-byte ACKs before Folklore's
    # source cursor and termination loop can observe them.  Filtering only at
    # payload accounting would let a late ACK spuriously extend the schedule.
    source = tuple(
        packet for packet in supplied if packet.length_bytes != profile.header_bytes
    )

    buffered = {direction: 0 for direction in _LIVE_DIRECTIONS}
    emissions: list[BufloEmission] = []
    cursor = 0
    timer_ms = 0
    capacity = profile.payload_capacity_bytes

    while timer_ms <= profile.tau_ms or cursor < len(source) or any(buffered.values()):
        while cursor < len(source) and source[cursor].monotonic_ms <= timer_ms:
            packet = source[cursor]
            buffered[packet.direction] += packet.length_bytes - profile.header_bytes
            cursor += 1

        for direction in directions:
            real = min(buffered[direction], capacity)
            buffered[direction] -= real
            emissions.append(
                BufloEmission(
                    monotonic_ms=timer_ms,
                    direction=direction,
                    length_bytes=profile.packet_size_bytes,
                    real_payload_bytes=real,
                    dummy_payload_bytes=capacity - real,
                )
            )
        timer_ms += profile.rho_ms

    return tuple(emissions)


@dataclass(frozen=True, slots=True)
class AccuracyReference:
    mean_percent: float
    plus_minus_percent: float


@dataclass(frozen=True, slots=True)
class BufloPaperResult:
    profile: BufloProfile
    extra_bandwidth_percent: float
    bandwidth_ratio: float
    latency_seconds: float
    ll: AccuracyReference
    herrmann: AccuracyReference
    panchenko: AccuracyReference
    vng_plus_plus: AccuracyReference
    panchenko_naive_bayes: AccuracyReference


def _accuracy(mean: float, plus_minus: float) -> AccuracyReference:
    return AccuracyReference(mean, plus_minus)


BUFLO_PAPER_RESULTS = (
    BufloPaperResult(
        BUFLO_PROFILES[0],
        93.5,
        1.935,
        6.0,
        _accuracy(18.4, 2.9),
        _accuracy(0.8, 0.0),
        _accuracy(27.3, 1.8),
        _accuracy(22.0, 2.1),
        _accuracy(21.4, 1.0),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[1],
        120.0,
        2.200,
        3.6,
        _accuracy(16.2, 1.6),
        _accuracy(0.8, 0.0),
        _accuracy(23.3, 3.3),
        _accuracy(18.3, 1.0),
        _accuracy(18.8, 1.4),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[2],
        140.5,
        2.405,
        2.4,
        _accuracy(16.3, 1.2),
        _accuracy(0.8, 0.0),
        _accuracy(20.9, 1.6),
        _accuracy(15.6, 1.2),
        _accuracy(17.9, 1.7),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[3],
        201.3,
        3.013,
        1.2,
        _accuracy(13.0, 0.8),
        _accuracy(0.8, 0.0),
        _accuracy(24.1, 1.8),
        _accuracy(18.4, 0.9),
        _accuracy(18.7, 1.0),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[4],
        129.2,
        2.292,
        6.0,
        _accuracy(12.7, 0.9),
        _accuracy(0.8, 0.0),
        _accuracy(14.1, 0.9),
        _accuracy(12.5, 0.8),
        _accuracy(13.2, 0.7),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[5],
        197.5,
        2.975,
        3.6,
        _accuracy(8.9, 1.0),
        _accuracy(0.8, 0.0),
        _accuracy(9.4, 1.3),
        _accuracy(8.2, 0.8),
        _accuracy(9.3, 1.3),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[6],
        364.5,
        4.645,
        2.4,
        _accuracy(5.4, 0.8),
        _accuracy(0.8, 0.0),
        _accuracy(7.3, 1.0),
        _accuracy(5.9, 1.0),
        _accuracy(6.8, 0.9),
    ),
    BufloPaperResult(
        BUFLO_PROFILES[7],
        418.8,
        5.188,
        1.2,
        _accuracy(4.4, 0.2),
        _accuracy(0.8, 0.0),
        _accuracy(5.1, 0.7),
        _accuracy(4.1, 0.8),
        _accuracy(5.3, 0.5),
    ),
)


@dataclass(frozen=True, slots=True)
class CsBufloParameters:
    """Defaults recovered from the authors' pinned WPES 2014 artifact."""

    initial_rho_us: int = 8_192
    lower_rho_us: int = 4_096
    upper_rho_us: int = 32_768
    first_adaptation_boundary_bytes: int = 16_384
    write_size_bytes: int = 548
    nominal_wire_packet_bytes: int = 600
    quiet_time_us: int = CSBUFLO_QUIET_TIME_US
    max_rate_samples: int = CSBUFLO_MAX_RATE_SAMPLES
    jitter_denominator: int = 100
    jitter_max_numerator: int = 200

    def __post_init__(self) -> None:
        values = (
            (self.initial_rho_us, "initial rho"),
            (self.lower_rho_us, "lower rho"),
            (self.upper_rho_us, "upper rho"),
            (self.first_adaptation_boundary_bytes, "first adaptation boundary"),
            (self.write_size_bytes, "write size"),
            (self.nominal_wire_packet_bytes, "nominal wire packet size"),
            (self.quiet_time_us, "quiet time"),
            (self.max_rate_samples, "maximum rate samples"),
            (self.jitter_denominator, "jitter denominator"),
            (self.jitter_max_numerator, "maximum jitter numerator"),
        )
        for value, label in values:
            _uint(value, f"CS-BuFLO {label}", positive=True)
        if not self.lower_rho_us <= self.initial_rho_us <= self.upper_rho_us:
            raise ValueError("CS-BuFLO initial rho must lie within its bounds")
        if self.jitter_max_numerator != 2 * self.jitter_denominator:
            raise ValueError("CS-BuFLO jitter range must be [0, 2 rho]")


CSBUFLO_WPES14_PARAMETERS = CsBufloParameters()


def csbuflo_rate_intervals_us(
    rho_stats_us: Sequence[int | None],
    *,
    lower_bound_us: int | None = None,
    upper_bound_us: int | None = None,
    max_samples: int | None = CSBUFLO_MAX_RATE_SAMPLES,
) -> tuple[int, ...]:
    """Return eligible same-burst intervals from timestamps and ``None`` separators."""

    if lower_bound_us is not None:
        _uint(lower_bound_us, "lower rho bound", positive=True)
    if upper_bound_us is not None:
        _uint(upper_bound_us, "upper rho bound", positive=True)
    if (
        lower_bound_us is not None
        and upper_bound_us is not None
        and lower_bound_us > upper_bound_us
    ):
        raise ValueError("lower rho bound exceeds upper rho bound")
    if max_samples is not None:
        _uint(max_samples, "maximum rho samples", positive=True)

    intervals: list[int] = []
    previous: int | None = None
    for sample in rho_stats_us:
        if sample is None:
            previous = None
            continue
        timestamp = _uint(sample, "rho statistic timestamp")
        if previous is not None:
            if timestamp < previous:
                raise ValueError("rho statistic timestamps must be monotonic within a burst")
            interval = timestamp - previous
            if lower_bound_us is not None:
                interval = max(interval, lower_bound_us)
            if upper_bound_us is not None:
                interval = min(interval, upper_bound_us)
            if interval <= 0:
                raise ValueError("a zero interval requires a positive artifact lower bound")
            intervals.append(interval)
        previous = timestamp
    if max_samples is not None and len(intervals) > max_samples:
        intervals = intervals[-max_samples:]
    return tuple(intervals)


class CsBufloEmptyRatePolicy(str, Enum):
    """The paper and pinned prototype disagree on an empty estimator window."""

    PAPER_RETAIN_CURRENT = "paper-retain-current"
    ARTIFACT_UPPER_BOUND = "artifact-upper-bound"


def csbuflo_estimate_rho_us(
    rho_stats_us: Sequence[int | None],
    current_rho_us: int,
    *,
    parameters: CsBufloParameters = CSBUFLO_WPES14_PARAMETERS,
    empty_policy: CsBufloEmptyRatePolicy | str = (CsBufloEmptyRatePolicy.PAPER_RETAIN_CURRENT),
) -> int:
    """Apply Algorithm 2 with artifact bounds and an upper integer median.

    The primary equation uses ``2**floor(log2(median))``.  The pinned source
    resolves the otherwise unspecified even-sample median as the upper middle
    element and clamps samples to 4.096--32.768 ms before quantization.  The
    explicit empty policy preserves the paper/prototype discrepancy instead of
    silently treating one as the other.
    """

    _uint(current_rho_us, "current rho", positive=True)
    try:
        resolved_empty_policy = CsBufloEmptyRatePolicy(empty_policy)
    except ValueError as error:
        raise ValueError("unknown CS-BuFLO empty-rate policy") from error
    intervals = csbuflo_rate_intervals_us(
        rho_stats_us,
        lower_bound_us=parameters.lower_rho_us,
        upper_bound_us=parameters.upper_rho_us,
        max_samples=parameters.max_rate_samples,
    )
    if not intervals:
        if resolved_empty_policy is CsBufloEmptyRatePolicy.ARTIFACT_UPPER_BOUND:
            return parameters.upper_rho_us
        return current_rho_us
    ordered = sorted(intervals)
    median = ordered[len(ordered) // 2]
    return 1 << (median.bit_length() - 1)


def csbuflo_estimate_directional_rho_us(
    rho_stats_us: Mapping[str, Sequence[int | None]],
    current_rho_us: Mapping[str, int],
    *,
    parameters: CsBufloParameters = CSBUFLO_WPES14_PARAMETERS,
    empty_policy: CsBufloEmptyRatePolicy | str = (CsBufloEmptyRatePolicy.PAPER_RETAIN_CURRENT),
) -> dict[str, int]:
    """Estimate each endpoint-relative direction without mixing its samples.

    The paper describes one estimator at each endpoint.  A centralized lab
    projection therefore needs two independent windows: outgoing samples model
    the local endpoint and incoming samples model the peer.  Each window is
    capped independently by the pinned prototype's 1,000-sample ring.
    """

    if set(rho_stats_us) != _DIRECTION_SET or set(current_rho_us) != _DIRECTION_SET:
        raise ValueError("directional rho inputs require exactly outgoing and incoming")
    return {
        direction: csbuflo_estimate_rho_us(
            rho_stats_us[direction],
            current_rho_us[direction],
            parameters=parameters,
            empty_policy=empty_policy,
        )
        for direction in _LIVE_DIRECTIONS
    }


@dataclass(frozen=True, slots=True)
class CsBufloRateUpdate:
    rho_star_us: int
    next_boundary_bytes: int
    adapted: bool
    retained_stats_us: tuple[int | None, ...]


def csbuflo_maybe_adapt_rate(
    *,
    total_sent_bytes: int,
    boundary_bytes: int,
    rho_stats_us: Sequence[int | None],
    current_rho_us: int,
    parameters: CsBufloParameters = CSBUFLO_WPES14_PARAMETERS,
    empty_policy: CsBufloEmptyRatePolicy | str = (CsBufloEmptyRatePolicy.PAPER_RETAIN_CURRENT),
) -> CsBufloRateUpdate:
    """Adapt once at a total-transmitted-byte boundary, then double it."""

    _uint(total_sent_bytes, "total transmitted bytes")
    _uint(boundary_bytes, "adaptation boundary", positive=True)
    stats = tuple(rho_stats_us)
    if total_sent_bytes < boundary_bytes:
        return CsBufloRateUpdate(current_rho_us, boundary_bytes, False, stats)
    return CsBufloRateUpdate(
        csbuflo_estimate_rho_us(
            stats,
            current_rho_us,
            parameters=parameters,
            empty_policy=empty_policy,
        ),
        boundary_bytes * 2,
        True,
        (),
    )


class DeterministicCsBufloJitter:
    """Seeded test oracle for the artifact's 201-point uniform jitter grid.

    This intentionally does not claim to reproduce ``arc4random``.  It makes
    the artifact's distribution and integer timing rule repeatable for golden
    tests while production implementations remain free to use a CSPRNG.
    """

    def __init__(self, seed: int) -> None:
        if type(seed) is not int:
            raise ValueError("CS-BuFLO jitter seed must be an integer")
        self._random = random.Random(seed)

    def next_delay_us(
        self,
        rho_star_us: int,
        *,
        parameters: CsBufloParameters = CSBUFLO_WPES14_PARAMETERS,
    ) -> int:
        _uint(rho_star_us, "rho star", positive=True)
        numerator = self._random.randrange(parameters.jitter_max_numerator + 1)
        return rho_star_us * numerator // parameters.jitter_denominator

    def delays_us(
        self,
        rho_star_us: int,
        count: int,
        *,
        parameters: CsBufloParameters = CSBUFLO_WPES14_PARAMETERS,
    ) -> tuple[int, ...]:
        _uint(count, "jitter sample count")
        return tuple(self.next_delay_us(rho_star_us, parameters=parameters) for _ in range(count))


class CsBufloPadding(str, Enum):
    PAYLOAD = "payload"
    TOTAL = "total"


@dataclass(frozen=True, slots=True)
class CsBufloPaddingProfile:
    name: str
    client: CsBufloPadding
    server: CsBufloPadding
    evaluated_in_main_results: bool
    author_archive_available: bool


CSBUFLO_PADDING_PROFILES = (
    CsBufloPaddingProfile("CPSP", CsBufloPadding.PAYLOAD, CsBufloPadding.PAYLOAD, True, True),
    CsBufloPaddingProfile("CPST", CsBufloPadding.PAYLOAD, CsBufloPadding.TOTAL, False, False),
    CsBufloPaddingProfile("CTSP", CsBufloPadding.TOTAL, CsBufloPadding.PAYLOAD, True, False),
    CsBufloPaddingProfile("CTST", CsBufloPadding.TOTAL, CsBufloPadding.TOTAL, False, False),
)


def _ceil_power_of_two(value: int) -> int:
    _uint(value, "power-of-two input", positive=True)
    return 1 << ((value - 1).bit_length())


def csbuflo_padding_target_bytes(
    real_bytes: int,
    junk_bytes: int,
    mode: CsBufloPadding | str,
) -> int:
    """Return the paper's mathematical stream-padding target."""

    real = _uint(real_bytes, "real byte count", positive=True)
    junk = _uint(junk_bytes, "junk byte count")
    try:
        padding = CsBufloPadding(mode)
    except ValueError as error:
        raise ValueError("CS-BuFLO padding mode must be payload or total") from error
    current = real + junk
    if padding is CsBufloPadding.TOTAL:
        return _ceil_power_of_two(current)
    quantum = _ceil_power_of_two(real)
    return ((current + quantum - 1) // quantum) * quantum


def csbuflo_fixed_writes_to_padding_target(
    real_bytes: int,
    junk_bytes: int,
    mode: CsBufloPadding | str,
    *,
    write_size_bytes: int = CSBUFLO_WPES14_PARAMETERS.write_size_bytes,
) -> int:
    """Return fixed writes needed to reach or cross the stream target."""

    write_size = _uint(write_size_bytes, "CS-BuFLO write size", positive=True)
    target = csbuflo_padding_target_bytes(real_bytes, junk_bytes, mode)
    remaining = target - real_bytes - junk_bytes
    return (remaining + write_size - 1) // write_size


def csbuflo_crossed_threshold(
    total_sent_bytes: int,
    *,
    packet_size_bytes: int = CSBUFLO_WPES14_PARAMETERS.write_size_bytes,
) -> bool:
    """Implement Algorithm 4's power-of-two crossing predicate safely."""

    total = _uint(total_sent_bytes, "total transmitted bytes")
    packet = _uint(packet_size_bytes, "CS-BuFLO packet size", positive=True)
    if total == 0:
        return False
    if total < packet:
        raise ValueError("total transmitted bytes cannot be smaller than the last packet")
    previous = total - packet
    if previous == 0:
        # This is the natural integer extension of floor(log2(0)) = -infinity.
        return True
    return previous.bit_length() < total.bit_length()


def csbuflo_channel_idle(
    *,
    on_load_event: bool,
    last_site_response_us: int | None,
    now_us: int,
    quiet_time_us: int = CSBUFLO_QUIET_TIME_US,
) -> bool:
    """Implement the paper's onLoad-or-strict-quiet-time idle rule."""

    if type(on_load_event) is not bool:
        raise ValueError("onLoad state must be boolean")
    now = _uint(now_us, "current time")
    quiet = _uint(quiet_time_us, "quiet time", positive=True)
    if on_load_event:
        return True
    if last_site_response_us is None:
        return False
    last = _uint(last_site_response_us, "last site response time")
    if last > now:
        raise ValueError("last site response cannot be in the future")
    return now > last + quiet


def csbuflo_done_transmitting(
    *,
    output_buffer_bytes: int,
    on_load_event: bool,
    last_site_response_us: int | None,
    now_us: int,
    padding_done: bool,
    total_sent_bytes: int,
    packet_size_bytes: int = CSBUFLO_WPES14_PARAMETERS.write_size_bytes,
    quiet_time_us: int = CSBUFLO_QUIET_TIME_US,
) -> bool:
    """Implement Algorithm 4 without conflating early termination and idleness."""

    output = _uint(output_buffer_bytes, "output buffer size")
    if type(padding_done) is not bool:
        raise ValueError("padding-done state must be boolean")
    return (
        output == 0
        and csbuflo_channel_idle(
            on_load_event=on_load_event,
            last_site_response_us=last_site_response_us,
            now_us=now_us,
            quiet_time_us=quiet_time_us,
        )
        and (
            padding_done
            or csbuflo_crossed_threshold(
                total_sent_bytes,
                packet_size_bytes=packet_size_bytes,
            )
        )
    )


@dataclass(frozen=True, slots=True)
class CsBufloMainResult:
    padding_profile: str
    sites: int
    early_termination: bool
    panchenko_percent: float
    vng_plus_plus_percent: float
    dlsvm_percent: float
    bandwidth_ratio: float
    latency_ratio: float


CSBUFLO_MAIN_RESULTS = (
    CsBufloMainResult("CTSP", 200, True, 18.0, 13.0, 20.6, 2.796, 3.271),
    CsBufloMainResult("CPSP", 200, True, 24.2, 16.5, 34.3, 2.289, 2.708),
    CsBufloMainResult("CTSP", 120, True, 23.4, 20.9, 28.9, 2.799, 3.444),
    CsBufloMainResult("CPSP", 120, True, 30.6, 22.5, 40.5, 2.300, 2.733),
)


@dataclass(frozen=True, slots=True)
class CsBufloAblationResult:
    padding_profile: str
    early_termination: bool
    sites: int
    bandwidth_ratio: float
    latency_ratio: float
    vng_plus_plus_percent: float


CSBUFLO_EARLY_TERMINATION_RESULTS = (
    CsBufloAblationResult("CTSP", True, 50, 3.59, 3.91, 29.0),
    CsBufloAblationResult("CTSP", False, 50, 3.73, 3.51, 29.6),
    CsBufloAblationResult("CPSP", True, 50, 2.60, 2.87, 34.2),
    CsBufloAblationResult("CPSP", False, 50, 3.42, 3.52, 36.0),
)


@dataclass(frozen=True, slots=True)
class CsBufloArchiveReference:
    source_id: str
    padding_profile: str
    sites: int
    trials_per_site: int
    total_records: int
    included_records: int
    zero_baseline_records: int
    defended_bytes: int
    baseline_bytes: int

    @property
    def bandwidth_ratio(self) -> float:
        return self.defended_bytes / self.baseline_bytes


CSBUFLO_CPSP_ARCHIVE_REFERENCE = CsBufloArchiveReference(
    source_id="csbuflo-cpsp-trace-archive",
    padding_profile="CPSP",
    sites=200,
    trials_per_site=20,
    total_records=4_000,
    included_records=3_824,
    zero_baseline_records=176,
    defended_bytes=7_592_598_380,
    baseline_bytes=3_326_013_453,
)


@dataclass(frozen=True, slots=True)
class ArchiveRatioAudit:
    source: Path
    total_records: int
    included_records: int
    zero_baseline_records: int
    defended_bytes: int
    baseline_bytes: int
    excluded_defended_bytes: int

    @property
    def finite_baseline_records(self) -> int:
        """Records for which the archive can report a finite per-trace ratio."""

        return self.included_records

    @property
    def bandwidth_ratio(self) -> float:
        return self.defended_bytes / self.baseline_bytes

    @property
    def extra_bandwidth_percent(self) -> float:
        return (self.bandwidth_ratio - 1.0) * 100.0

    @property
    def all_defended_bytes(self) -> int:
        """Diagnostic numerator before invalid zero-baseline pairs are excluded."""

        return self.defended_bytes + self.excluded_defended_bytes

    @property
    def all_rows_ratio(self) -> float:
        """Non-reference diagnostic that retains invalid pairs in the numerator."""

        return self.all_defended_bytes / self.baseline_bytes


def audit_csbuflo_archive(path: Path) -> ArchiveRatioAudit:
    """Audit aggregate bandwidth from an external archive or ``overhead.txt``.

    The function performs no download and never extracts a tar member.  A
    directory may be either the extracted archive root or its parent, provided
    it contains exactly one file named ``overhead.txt``.  Records whose paired
    baseline is zero are invalid for the paper's paired ratio-of-expectations
    calculation, so both sides of those pairs are excluded from the reference
    numerator and denominator.  Their defended bytes remain available as a
    separate diagnostic.
    """

    source = Path(path)
    text = _read_overhead_text(source)
    defended_sum = 0
    baseline_sum = 0
    excluded_defended_sum = 0
    total_records = 0
    included_records = 0
    zero_baseline_records = 0
    seen: set[str] = set()

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        match = _OVERHEAD_LINE_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid CS-BuFLO overhead record at line {line_number}")
        record = match.group("record")
        if record in seen:
            raise ValueError(f"duplicate CS-BuFLO overhead record: {record}")
        seen.add(record)
        defended = int(match.group("defended"))
        baseline = int(match.group("baseline"))
        ratio_text = match.group("ratio")
        total_records += 1
        if baseline == 0:
            if ratio_text != "inf":
                raise ValueError(f"zero baseline must report inf at line {line_number}")
            zero_baseline_records += 1
            excluded_defended_sum += defended
            continue
        if ratio_text == "inf":
            raise ValueError(f"finite baseline reports inf at line {line_number}")
        reported = float(ratio_text)
        calculated = defended / baseline
        if not math.isclose(reported, calculated, rel_tol=5e-7, abs_tol=5e-7):
            raise ValueError(f"reported ratio mismatch at line {line_number}")
        defended_sum += defended
        baseline_sum += baseline
        included_records += 1

    if total_records == 0 or included_records == 0 or baseline_sum == 0:
        raise ValueError("CS-BuFLO overhead evidence contains no usable records")
    return ArchiveRatioAudit(
        source.resolve(),
        total_records,
        included_records,
        zero_baseline_records,
        defended_sum,
        baseline_sum,
        excluded_defended_sum,
    )


def _read_overhead_text(path: Path) -> str:
    if path.is_dir():
        candidates = [candidate for candidate in path.rglob("overhead.txt") if candidate.is_file()]
        if len(candidates) != 1:
            raise ValueError("directory must contain exactly one overhead.txt")
        return _read_bounded_text(candidates[0])
    if not path.is_file():
        raise ValueError(f"CS-BuFLO archive path is not a regular file: {path}")
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            members = [
                member
                for member in archive.getmembers()
                if Path(member.name).name == "overhead.txt"
            ]
            if len(members) != 1 or not members[0].isfile():
                raise ValueError("archive must contain exactly one regular overhead.txt")
            member = members[0]
            if member.size > MAX_REFERENCE_TEXT_BYTES:
                raise ValueError("archive overhead.txt exceeds the reference size limit")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("archive overhead.txt could not be read")
            try:
                return extracted.read(MAX_REFERENCE_TEXT_BYTES + 1).decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("archive overhead.txt is not UTF-8") from error
    return _read_bounded_text(path)


def _read_bounded_text(path: Path) -> str:
    if path.stat().st_size > MAX_REFERENCE_TEXT_BYTES:
        raise ValueError("overhead.txt exceeds the reference size limit")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("overhead.txt is not UTF-8") from error


def _accuracy_dict(value: AccuracyReference) -> dict[str, float]:
    return {
        "mean_percent": value.mean_percent,
        "plus_minus_percent": value.plus_minus_percent,
    }


def buflo_reference_document() -> dict[str, Any]:
    """Return the canonical, serializable IEEE S&P 2012 reference document."""

    return {
        "artifact_type": "qcsd-primary-reference",
        "doi": "10.1109/SP.2012.28",
        "reference_id": BUFLO_REFERENCE_ID,
        "schema_version": REFERENCE_SCHEMA_VERSION,
        "source_basis": ["dyer-paper-pdf", "dyer-folklore-py", "dyer-overhead-parser-py"],
        "algorithm": {
            "author_source_directions_per_tick": ["incoming", "outgoing"],
            "live_adaptation_directions_per_tick": ["outgoing", "incoming"],
            "paper_bidirectional_order": "unspecified-independent-endpoints",
            "first_tick_ms": 0,
            "header_bytes": BUFLO_HEADER_BYTES,
            "minimum_duration_inclusive": True,
            "termination": "source-exhausted-and-both-real-buffers-empty-and-timer>tau",
        },
        "metric_conventions": {
            "bandwidth_ratio": "defended_bytes/baseline_bytes",
            "figure_12_bandwidth": "additional-overhead-percent",
            "figure_12_latency": "absolute-seconds-not-ratio",
        },
        "published_results": [
            {
                "profile": {
                    "d_bytes": result.profile.packet_size_bytes,
                    "rho_ms": result.profile.rho_ms,
                    "tau_ms": result.profile.tau_ms,
                },
                "extra_bandwidth_percent": result.extra_bandwidth_percent,
                "bandwidth_ratio": result.bandwidth_ratio,
                "latency_seconds": result.latency_seconds,
                "accuracy": {
                    "herrmann": _accuracy_dict(result.herrmann),
                    "ll": _accuracy_dict(result.ll),
                    "panchenko": _accuracy_dict(result.panchenko),
                    "panchenko_naive_bayes": _accuracy_dict(result.panchenko_naive_bayes),
                    "vng_plus_plus": _accuracy_dict(result.vng_plus_plus),
                },
            }
            for result in BUFLO_PAPER_RESULTS
        ],
    }


def csbuflo_reference_document() -> dict[str, Any]:
    """Return the canonical, serializable WPES 2014 reference document."""

    parameters = CSBUFLO_WPES14_PARAMETERS
    return {
        "artifact_type": "qcsd-primary-reference",
        "doi": "10.1145/2665943.2665949",
        "reference_id": CSBUFLO_REFERENCE_ID,
        "schema_version": REFERENCE_SCHEMA_VERSION,
        "source_basis": [
            "csbuflo-paper-pdf",
            "csbuflo-preprint-pdf",
            "csbuflo-misc-h",
            "csbuflo-misc-c",
            "csbuflo-packet-c",
            "csbuflo-clientloop-c",
            "csbuflo-serverloop-c",
            "csbuflo-cpsp-trace-archive",
        ],
        "artifact_defaults": {
            "first_adaptation_boundary_bytes": parameters.first_adaptation_boundary_bytes,
            "initial_rho_us": parameters.initial_rho_us,
            "jitter_grid_numerators_inclusive": [0, parameters.jitter_max_numerator],
            "jitter_grid_scale_denominator": parameters.jitter_denominator,
            "lower_rho_us": parameters.lower_rho_us,
            "max_rate_samples_per_direction": parameters.max_rate_samples,
            "nominal_wire_packet_bytes": parameters.nominal_wire_packet_bytes,
            "quiet_time_us": parameters.quiet_time_us,
            "upper_rho_us": parameters.upper_rho_us,
            "write_size_bytes": parameters.write_size_bytes,
        },
        "author_archive_reference": {
            "bandwidth_ratio": CSBUFLO_CPSP_ARCHIVE_REFERENCE.bandwidth_ratio,
            "baseline_bytes": CSBUFLO_CPSP_ARCHIVE_REFERENCE.baseline_bytes,
            "defended_bytes": CSBUFLO_CPSP_ARCHIVE_REFERENCE.defended_bytes,
            "included_records": CSBUFLO_CPSP_ARCHIVE_REFERENCE.included_records,
            "padding_profile": CSBUFLO_CPSP_ARCHIVE_REFERENCE.padding_profile,
            "sites": CSBUFLO_CPSP_ARCHIVE_REFERENCE.sites,
            "source_id": CSBUFLO_CPSP_ARCHIVE_REFERENCE.source_id,
            "total_records": CSBUFLO_CPSP_ARCHIVE_REFERENCE.total_records,
            "trials_per_site": CSBUFLO_CPSP_ARCHIVE_REFERENCE.trials_per_site,
            "zero_baseline_records": CSBUFLO_CPSP_ARCHIVE_REFERENCE.zero_baseline_records,
        },
        "algorithm_resolutions": {
            "adaptation_counter": "total-actually-transmitted-real-plus-junk-bytes",
            "adaptation_scope": "independent-per-endpoint-direction",
            "author_commit_active_padding": "CPSP-payload-at-both-endpoints",
            "author_commit_total_padding": "commented-inactive-source-expression-only",
            "empty_rate_sample_paper": "retain-current-rho-per-algorithm-2",
            "empty_rate_sample_pinned_artifact": "set-upper-rho",
            "rate_quantization": "2**floor(log2(upper-integer-median-interval))",
            "termination": "algorithm-4-buffer-idle-and-padding-done-or-power-of-two-crossing",
        },
        "metric_conventions": {
            "bandwidth_ratio": "ratio-of-expectations-not-mean-per-trace-ratio",
            "latency_ratio": "ratio-of-expected-total-trace-duration",
        },
        "paper_internal_discrepancies": [dict(_CSBUFLO_RATE_QUANTIZATION_DISCREPANCY)],
        "padding_profiles": {
            profile.name: {
                "author_archive_available": profile.author_archive_available,
                "client_padding": profile.client.value,
                "evaluated_in_main_results": profile.evaluated_in_main_results,
                "server_padding": profile.server.value,
            }
            for profile in CSBUFLO_PADDING_PROFILES
        },
        "main_results": [
            {
                "bandwidth_ratio": result.bandwidth_ratio,
                "dlsvm_percent": result.dlsvm_percent,
                "early_termination": result.early_termination,
                "latency_ratio": result.latency_ratio,
                "padding_profile": result.padding_profile,
                "panchenko_percent": result.panchenko_percent,
                "sites": result.sites,
                "vng_plus_plus_percent": result.vng_plus_plus_percent,
            }
            for result in CSBUFLO_MAIN_RESULTS
        ],
        "early_termination_ablation": [
            {
                "bandwidth_ratio": result.bandwidth_ratio,
                "early_termination": result.early_termination,
                "latency_ratio": result.latency_ratio,
                "padding_profile": result.padding_profile,
                "sites": result.sites,
                "vng_plus_plus_percent": result.vng_plus_plus_percent,
            }
            for result in CSBUFLO_EARLY_TERMINATION_RESULTS
        ],
    }


_RECEIPT_SOURCES: dict[str, tuple[dict[str, str], ...]] = {
    BUFLO_REFERENCE_ID: (
        {
            "kind": "primary-paper",
            "sha256": "a68dd316e37bc749cfd0f5becdb9b2faa77e7f6fdb575d3e067da2d9018297cc",
            "source_id": "dyer-paper-pdf",
            "url": "https://rist.tech.cornell.edu/papers/trafanal.pdf",
        },
        {
            "git_commit": "372ced4c84b867086394cbd736b089e5cad4969b",
            "kind": "author-reference-code",
            "sha256": "d49c6475e079ca3f8d62acd739008a270d7130d41fc8f24cf239aa273aee85c3",
            "source_id": "dyer-folklore-py",
            "url": (
                "https://raw.githubusercontent.com/kpdyer/website-fingerprinting/"
                "372ced4c84b867086394cbd736b089e5cad4969b/countermeasures/Folklore.py"
            ),
        },
        {
            "git_commit": "372ced4c84b867086394cbd736b089e5cad4969b",
            "kind": "author-reference-dependency",
            "sha256": "7f96377ec570485d7df14e24d0199e359582f1eea62eeaf2ede5c0e1581c0139",
            "source_id": "dyer-config-py",
            "url": (
                "https://raw.githubusercontent.com/kpdyer/website-fingerprinting/"
                "372ced4c84b867086394cbd736b089e5cad4969b/config.py"
            ),
        },
        {
            "git_commit": "372ced4c84b867086394cbd736b089e5cad4969b",
            "kind": "author-reference-dependency",
            "sha256": "f91ab32df77845e01b076b07557fb4709251eb1ce6b8846a5129a563ea01f7b5",
            "source_id": "dyer-packet-py",
            "url": (
                "https://raw.githubusercontent.com/kpdyer/website-fingerprinting/"
                "372ced4c84b867086394cbd736b089e5cad4969b/Packet.py"
            ),
        },
        {
            "git_commit": "372ced4c84b867086394cbd736b089e5cad4969b",
            "kind": "author-reference-dependency",
            "sha256": "b5a76d0dc56a6275c754e716bdf5f5abcf27fbec6572c4ae51a929c39eef1336",
            "source_id": "dyer-trace-py",
            "url": (
                "https://raw.githubusercontent.com/kpdyer/website-fingerprinting/"
                "372ced4c84b867086394cbd736b089e5cad4969b/Trace.py"
            ),
        },
        {
            "git_commit": "372ced4c84b867086394cbd736b089e5cad4969b",
            "kind": "author-reference-dependency",
            "sha256": "cd5ac223ad9fca42a3b9ef321f28eec96dbbba44f8c1f8404373339ecc581878",
            "source_id": "dyer-webpage-py",
            "url": (
                "https://raw.githubusercontent.com/kpdyer/website-fingerprinting/"
                "372ced4c84b867086394cbd736b089e5cad4969b/Webpage.py"
            ),
        },
        {
            "git_commit": "372ced4c84b867086394cbd736b089e5cad4969b",
            "kind": "author-reference-code",
            "sha256": "1f6d593276ca36e006399fb7bfaed67cbef59528b85fe60840241cb2dc1f0996",
            "source_id": "dyer-overhead-parser-py",
            "url": (
                "https://raw.githubusercontent.com/kpdyer/website-fingerprinting/"
                "372ced4c84b867086394cbd736b089e5cad4969b/parseResultsFile.py"
            ),
        },
    ),
    CSBUFLO_REFERENCE_ID: (
        {
            "kind": "primary-paper",
            "sha256": "200c8c58e8e8a6859f2baaa15299351fb0ad832bc3322b5553dfa88abcdab43d",
            "source_id": "csbuflo-paper-pdf",
            "url": "https://www.freehaven.net/anonbib/cache/wpes14-csbuflo.pdf",
        },
        {
            "kind": "primary-preprint",
            "sha256": "a2ae01af3bb41dc403d395b19b3a9e2bbcaaccce7530bf3749abf83e2908260f",
            "source_id": "csbuflo-preprint-pdf",
            "url": "https://arxiv.org/pdf/1401.6022",
        },
        {
            "git_commit": "43252f6e463ba71c43490af3f5a63308134f3bbe",
            "kind": "author-reference-code",
            "sha256": "428ca512066b89641bc355764ba6943938f0eca0839ab2460c3500f0adb1c822",
            "source_id": "csbuflo-misc-h",
            "url": (
                "https://raw.githubusercontent.com/xiang-cai/CSBuFLO/"
                "43252f6e463ba71c43490af3f5a63308134f3bbe/modified_openssh-5.9p1/misc.h"
            ),
        },
        {
            "git_commit": "43252f6e463ba71c43490af3f5a63308134f3bbe",
            "kind": "author-reference-code",
            "sha256": "fedbe65ccd06e55465b71176ef1d625e18be49cc165d258fce9ce9814fd0924c",
            "source_id": "csbuflo-misc-c",
            "url": (
                "https://raw.githubusercontent.com/xiang-cai/CSBuFLO/"
                "43252f6e463ba71c43490af3f5a63308134f3bbe/modified_openssh-5.9p1/misc.c"
            ),
        },
        {
            "git_commit": "43252f6e463ba71c43490af3f5a63308134f3bbe",
            "kind": "author-reference-code",
            "sha256": "a3af77c131eccfe1fd0787cc1063870bebbf0e3fe0c2975e4143ed9c86b0cec0",
            "source_id": "csbuflo-packet-c",
            "url": (
                "https://raw.githubusercontent.com/xiang-cai/CSBuFLO/"
                "43252f6e463ba71c43490af3f5a63308134f3bbe/modified_openssh-5.9p1/packet.c"
            ),
        },
        {
            "git_commit": "43252f6e463ba71c43490af3f5a63308134f3bbe",
            "kind": "author-reference-code",
            "sha256": "6f0148c8891756e39980edf47f2d5fbc254d2da7b4a8096a678cf3bb7777a36e",
            "source_id": "csbuflo-clientloop-c",
            "url": (
                "https://raw.githubusercontent.com/xiang-cai/CSBuFLO/"
                "43252f6e463ba71c43490af3f5a63308134f3bbe/"
                "modified_openssh-5.9p1/clientloop.c"
            ),
        },
        {
            "git_commit": "43252f6e463ba71c43490af3f5a63308134f3bbe",
            "kind": "author-reference-code",
            "sha256": "abc798cecb918d5c89ccec825224d543862e95a9650334bb0b5d4dd99e17a3a9",
            "source_id": "csbuflo-serverloop-c",
            "url": (
                "https://raw.githubusercontent.com/xiang-cai/CSBuFLO/"
                "43252f6e463ba71c43490af3f5a63308134f3bbe/"
                "modified_openssh-5.9p1/serverloop.c"
            ),
        },
        {
            "git_commit": "43252f6e463ba71c43490af3f5a63308134f3bbe",
            "kind": "author-reference-traces",
            "sha256": "225bb69da7cc8fa8df0a60178cda877a2e528db58f80f01b9894dce25aeabf55",
            "source_id": "csbuflo-cpsp-trace-archive",
            "url": (
                "https://raw.githubusercontent.com/xiang-cai/CSBuFLO/"
                "43252f6e463ba71c43490af3f5a63308134f3bbe/"
                "log_interval_tau_200_20_allmedian_2t_600_CMSM_paddingdone_pairs.tar.gz"
            ),
        },
    ),
}


@dataclass(frozen=True, slots=True)
class ReferenceReceiptValidation:
    reference_id: str
    reference_path: Path
    reference_sha256: str
    receipt_path: Path
    receipt_sha256: str
    verified_external_sources: tuple[str, ...]


def validate_reference_receipt(
    reference_path: Path,
    *,
    receipt_path: Path | None = None,
    external_sources: Mapping[str, Path] | None = None,
) -> ReferenceReceiptValidation:
    """Validate a versioned reference document and its primary-source receipt."""

    reference = Path(reference_path)
    receipt = (
        Path(receipt_path) if receipt_path is not None else reference.with_suffix(".receipt.json")
    )
    for path in (reference, receipt):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"reference evidence is not a regular file: {path}")

    document = load_json(reference)
    if document == buflo_reference_document():
        reference_id = BUFLO_REFERENCE_ID
    elif document == csbuflo_reference_document():
        reference_id = CSBUFLO_REFERENCE_ID
    else:
        raise ValueError(f"reference document is not a canonical supported version: {reference}")
    reference_digest = sha256_file(reference)

    receipt_value = load_json(receipt)
    expected_keys = {
        "artifact_type",
        "clean_room",
        "reference_file",
        "reference_id",
        "schema_version",
        "sources",
    }
    if not isinstance(receipt_value, dict) or set(receipt_value) != expected_keys:
        raise ValueError(f"reference receipt has invalid keys: {receipt}")
    if (
        receipt_value["schema_version"] != RECEIPT_SCHEMA_VERSION
        or receipt_value["artifact_type"] != "qcsd-primary-reference-receipt"
        or receipt_value["clean_room"] is not True
        or receipt_value["reference_id"] != reference_id
    ):
        raise ValueError(f"reference receipt identity is invalid: {receipt}")
    file_binding = receipt_value["reference_file"]
    if not isinstance(file_binding, dict) or set(file_binding) != {"path", "sha256"}:
        raise ValueError(f"reference receipt file binding is invalid: {receipt}")
    if file_binding["path"] != reference.name or file_binding["sha256"] != reference_digest:
        raise ValueError(f"reference receipt SHA-256 mismatch: {reference}")

    expected_sources = _RECEIPT_SOURCES[reference_id]
    if receipt_value["sources"] != list(expected_sources):
        raise ValueError(f"reference receipt sources are not canonical: {receipt}")
    _validate_receipt_sources(expected_sources, receipt)

    supplied = dict(external_sources or {})
    expected_by_id = {source["source_id"]: source for source in expected_sources}
    unknown = set(supplied) - set(expected_by_id)
    if unknown:
        raise ValueError(f"unknown external reference sources: {sorted(unknown)}")
    verified = []
    for source_id, path_value in sorted(supplied.items()):
        path = Path(path_value)
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"external reference source is not a regular file: {path}")
        if sha256_file(path) != expected_by_id[source_id]["sha256"]:
            raise ValueError(f"external reference source SHA-256 mismatch: {source_id}")
        verified.append(source_id)

    return ReferenceReceiptValidation(
        reference_id,
        reference.resolve(),
        reference_digest,
        receipt.resolve(),
        sha256_file(receipt),
        tuple(verified),
    )


def _validate_receipt_sources(sources: Sequence[Mapping[str, str]], receipt: Path) -> None:
    seen: set[str] = set()
    for source in sources:
        required = {"kind", "sha256", "source_id", "url"}
        if set(source) not in (required, required | {"git_commit"}):
            raise ValueError(f"reference source has invalid keys: {receipt}")
        source_id = source["source_id"]
        if not source_id or source_id in seen:
            raise ValueError(f"reference source identifiers are invalid: {receipt}")
        seen.add(source_id)
        if _SHA256_RE.fullmatch(source["sha256"]) is None:
            raise ValueError(f"reference source SHA-256 is invalid: {receipt}")
        if not source["url"].startswith("https://"):
            raise ValueError(f"reference source URL is invalid: {receipt}")
        commit = source.get("git_commit")
        if commit is not None and _COMMIT_RE.fullmatch(commit) is None:
            raise ValueError(f"reference source commit is invalid: {receipt}")


_GATE_RELATIVE_BINDINGS = {
    "dyer-paper-pdf": Path("trafanal.pdf"),
    "dyer-folklore-py": Path("website-fingerprinting/countermeasures/Folklore.py"),
    "dyer-config-py": Path("website-fingerprinting/config.py"),
    "dyer-packet-py": Path("website-fingerprinting/Packet.py"),
    "dyer-trace-py": Path("website-fingerprinting/Trace.py"),
    "dyer-webpage-py": Path("website-fingerprinting/Webpage.py"),
    "dyer-overhead-parser-py": Path("website-fingerprinting/parseResultsFile.py"),
    "csbuflo-paper-pdf": Path("wpes14-csbuflo.pdf"),
    "csbuflo-preprint-pdf": Path("csbuflo-preprint.pdf"),
    "csbuflo-misc-h": Path("CSBuFLO/modified_openssh-5.9p1/misc.h"),
    "csbuflo-misc-c": Path("CSBuFLO/modified_openssh-5.9p1/misc.c"),
    "csbuflo-packet-c": Path("CSBuFLO/modified_openssh-5.9p1/packet.c"),
    "csbuflo-clientloop-c": Path("CSBuFLO/modified_openssh-5.9p1/clientloop.c"),
    "csbuflo-serverloop-c": Path("CSBuFLO/modified_openssh-5.9p1/serverloop.c"),
    "csbuflo-cpsp-trace-archive": Path(
        "CSBuFLO/log_interval_tau_200_20_allmedian_2t_600_CMSM_paddingdone_pairs.tar.gz"
    ),
}
_GATE_REQUIRED_SOURCE_IDS = tuple(_GATE_RELATIVE_BINDINGS)
_BUFLO_AUTHOR_SOURCE_MODULES = {
    "Packet": ("dyer-packet-py", "Packet.py"),
    "Webpage": ("dyer-webpage-py", "Webpage.py"),
    "Trace": ("dyer-trace-py", "Trace.py"),
    "Folklore": ("dyer-folklore-py", "countermeasures/Folklore.py"),
}
_BUFLO_GATE_PACKETS = tuple(
    [BufloSourcePacket(0, "outgoing", 100) for _ in range(20)]
    + [BufloSourcePacket(5, "incoming", 150) for _ in range(3)]
    + [BufloSourcePacket(85, "outgoing", 100)]
)
_BUFLO_AUTHOR_RUNNER = r"""
import hashlib
import json
import os
import stat
import sys
import types

repo = os.path.realpath(sys.argv[1])
request = json.load(sys.stdin)
expected_layout = {
    "Packet": "Packet.py",
    "Webpage": "Webpage.py",
    "Trace": "Trace.py",
    "Folklore": "countermeasures/Folklore.py",
}
sources = request.get("author_sources")
if not isinstance(sources, dict) or set(sources) != set(expected_layout):
    raise RuntimeError("BuFLO author source manifest is invalid")

# Isolated mode excludes the working directory, and no author-tree path is ever
# added.  Author modules are opened, hash-checked, compiled, and executed from
# their receipted source bytes, so Python's import machinery cannot select a
# timestamp-valid or hash-valid bytecode cache from the external tree.
for entry in sys.path:
    if not entry:
        raise RuntimeError("isolated BuFLO author runner has an empty import path entry")
    resolved_entry = os.path.realpath(entry)
    try:
        inside_repo = os.path.commonpath((repo, resolved_entry)) == repo
    except ValueError:
        inside_repo = False
    if inside_repo:
        raise RuntimeError("BuFLO author tree unexpectedly appears on sys.path")


def load_receipted_source(module_name):
    source = sources[module_name]
    if not isinstance(source, dict) or set(source) != {"relative_path", "sha256"}:
        raise RuntimeError("BuFLO author source binding is invalid: " + module_name)
    relative_path = source["relative_path"]
    digest = source["sha256"]
    if relative_path != expected_layout[module_name]:
        raise RuntimeError("BuFLO author source layout is invalid: " + module_name)
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise RuntimeError("BuFLO author source digest is invalid: " + module_name)
    source_path = os.path.normpath(os.path.join(repo, relative_path))
    try:
        inside_repo = os.path.commonpath((repo, source_path)) == repo
    except ValueError:
        inside_repo = False
    if not inside_repo:
        raise RuntimeError("BuFLO author source escaped its root: " + module_name)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source_path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("BuFLO author source is not regular: " + module_name)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            source_bytes = handle.read()
    finally:
        os.close(descriptor)
    if hashlib.sha256(source_bytes).hexdigest() != digest:
        raise RuntimeError("BuFLO author source digest mismatch: " + module_name)
    module = types.ModuleType(module_name)
    module.__file__ = source_path
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(source_bytes, source_path, "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module

# The historical repository's configuration module contains Python 2 print
# syntax.  The trace oracle reads only IGNORE_ACK, so provide that single
# configuration input without modifying or translating any author source.
config = types.ModuleType("config")
config.IGNORE_ACK = True
sys.modules["config"] = config

Packet = load_receipted_source("Packet").Packet
load_receipted_source("Webpage")
Trace = load_receipted_source("Trace").Trace
Folklore = load_receipted_source("Folklore").Folklore

result = {}
for profile in request["profiles"]:
    trace = Trace(1)
    for timestamp, direction, length in request["packets"]:
        author_direction = Packet.UP if direction == "outgoing" else Packet.DOWN
        trace.addPacket(Packet(author_direction, timestamp, length))
    Folklore.MILLISECONDS_TO_RUN = profile["tau_ms"]
    Folklore.TIMER_CLOCK_SPEED = profile["rho_ms"]
    Folklore.FIXED_PACKET_LEN = profile["d_bytes"]
    transformed = Folklore.applyCountermeasure(trace)
    result[profile["key"]] = [
        [
            packet.getTime(),
            "outgoing" if packet.getDirection() == Packet.UP else "incoming",
            packet.getLength(),
        ]
        for packet in transformed.getPackets()
    ]
json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
"""


@dataclass(frozen=True, slots=True)
class ReferenceGateResult:
    receipt_path: Path
    receipt_sha256: str
    profiles_checked: int
    archive_audit: ArchiveRatioAudit


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reference_root() -> Path:
    return LAB_ROOT / "config/reference/buflo-csbuflo"


def _resolve_gate_bindings(
    external_root_or_bindings: Path | Mapping[str, Path],
) -> dict[str, Path]:
    if isinstance(external_root_or_bindings, Mapping):
        supplied = {str(key): Path(value) for key, value in external_root_or_bindings.items()}
        unknown = set(supplied) - {
            source["source_id"] for sources in _RECEIPT_SOURCES.values() for source in sources
        }
        if unknown:
            raise ValueError(f"unknown gate source bindings: {sorted(unknown)}")
        missing = set(_GATE_REQUIRED_SOURCE_IDS) - set(supplied)
        if missing:
            raise ValueError(f"missing gate source bindings: {sorted(missing)}")
        return {source_id: supplied[source_id] for source_id in _GATE_REQUIRED_SOURCE_IDS}
    root = Path(external_root_or_bindings)
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"reference gate root is not a regular directory: {root}")
    return {source_id: root / relative for source_id, relative in _GATE_RELATIVE_BINDINGS.items()}


def _validate_gate_bindings(bindings: Mapping[str, Path]) -> list[dict[str, str]]:
    expected = {
        source["source_id"]: source for sources in _RECEIPT_SOURCES.values() for source in sources
    }
    validated: list[dict[str, str]] = []
    for source_id in sorted(_GATE_REQUIRED_SOURCE_IDS):
        path = Path(bindings[source_id])
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"reference gate input is not a regular file: {path}")
        digest = sha256_file(path)
        if digest != expected[source_id]["sha256"]:
            raise ValueError(f"reference gate input SHA-256 mismatch: {source_id}")
        record = {
            "sha256": digest,
            "source_id": source_id,
            "url": expected[source_id]["url"],
        }
        if "git_commit" in expected[source_id]:
            record["git_commit"] = expected[source_id]["git_commit"]
        validated.append(record)

    folklore = Path(bindings["dyer-folklore-py"]).resolve()
    author_root = folklore.parents[1]
    expected_layout = {
        "dyer-config-py": author_root / "config.py",
        "dyer-packet-py": author_root / "Packet.py",
        "dyer-trace-py": author_root / "Trace.py",
        "dyer-webpage-py": author_root / "Webpage.py",
        "dyer-overhead-parser-py": author_root / "parseResultsFile.py",
    }
    if folklore != author_root / "countermeasures/Folklore.py" or any(
        Path(bindings[source_id]).resolve() != expected_path
        for source_id, expected_path in expected_layout.items()
    ):
        raise ValueError("BuFLO author inputs do not preserve the pinned repository layout")

    csbuflo_root = Path(bindings["csbuflo-misc-c"]).resolve().parent
    csbuflo_layout = {
        "csbuflo-misc-h": csbuflo_root / "misc.h",
        "csbuflo-misc-c": csbuflo_root / "misc.c",
        "csbuflo-packet-c": csbuflo_root / "packet.c",
        "csbuflo-clientloop-c": csbuflo_root / "clientloop.c",
        "csbuflo-serverloop-c": csbuflo_root / "serverloop.c",
    }
    if csbuflo_root.name != "modified_openssh-5.9p1" or any(
        Path(bindings[source_id]).resolve() != expected_path
        for source_id, expected_path in csbuflo_layout.items()
    ):
        raise ValueError("CS-BuFLO author inputs do not preserve the pinned repository layout")
    return validated


def _buflo_projection(
    profile: BufloProfile,
    order: BufloDirectionOrder,
) -> list[list[int | str]]:
    return [
        [emission.monotonic_ms, emission.direction, emission.length_bytes]
        for emission in transform_buflo(
            _BUFLO_GATE_PACKETS,
            profile,
            direction_order=order,
        )
    ]


def _run_buflo_author_gate(folklore_path: Path) -> tuple[list[dict[str, object]], str]:
    """Run only hash-validated author source; never import author-tree bytecode."""

    author_root = folklore_path.resolve().parents[1]
    receipt_sources = {
        source["source_id"]: source
        for sources in _RECEIPT_SOURCES.values()
        for source in sources
    }
    request = {
        "author_sources": {
            module_name: {
                "relative_path": relative_path,
                "sha256": receipt_sources[source_id]["sha256"],
            }
            for module_name, (source_id, relative_path) in _BUFLO_AUTHOR_SOURCE_MODULES.items()
        },
        "packets": [
            [packet.monotonic_ms, packet.direction, packet.length_bytes]
            for packet in _BUFLO_GATE_PACKETS
        ],
        "profiles": [
            {
                "d_bytes": profile.packet_size_bytes,
                "key": profile.key,
                "rho_ms": profile.rho_ms,
                "tau_ms": profile.tau_ms,
            }
            for profile in BUFLO_PROFILES
        ],
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            _BUFLO_AUTHOR_RUNNER,
            os.fspath(author_root),
        ],
        cwd=author_root,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        input=json.dumps(request, sort_keys=True, separators=(",", ":")),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip().splitlines()
        detail = error[-1] if error else f"exit {completed.returncode}"
        raise ValueError(f"isolated BuFLO author runner failed: {detail}")
    try:
        author_result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("isolated BuFLO author runner returned invalid JSON") from error

    rows: list[dict[str, object]] = []
    aggregate_source: dict[str, object] = {}
    for profile in BUFLO_PROFILES:
        source_projection = _buflo_projection(
            profile,
            BufloDirectionOrder.SOURCE_INCOMING_FIRST,
        )
        live_projection = _buflo_projection(
            profile,
            BufloDirectionOrder.LIVE_OUTGOING_FIRST,
        )
        if author_result.get(profile.key) != source_projection:
            raise ValueError(f"BuFLO author conformance mismatch: {profile.key}")
        if sorted(source_projection) != sorted(live_projection):
            raise ValueError(f"BuFLO live-order adaptation changed events: {profile.key}")
        aggregate_source[profile.key] = source_projection
        rows.append(
            {
                "event_count": len(source_projection),
                "live_order_sha256": _canonical_digest(live_projection),
                "profile": profile.key,
                "source_match": True,
                "source_order_sha256": _canonical_digest(source_projection),
            }
        )
    return rows, _canonical_digest(aggregate_source)


_CSBUFLO_CLIENT_TERMINAL_CONDITION = (
    "outbuf_len == 0 && target_sent_bytes + TARGET_QUEUE_LEN > total_sent_bytes && "
    "total_sent_bytes + TARGET_QUEUE_LEN > target_sent_bytes"
)
_CSBUFLO_SERVER_TERMINAL_CONDITION = (
    "outbuf_len <= 32 && (target_sent_bytes + TARGET_QUEUE_LEN > total_sent_bytes && "
    "total_sent_bytes + TARGET_QUEUE_LEN > target_sent_bytes)"
)
_CSBUFLO_EARLY_OUTER_CONDITION = "get_transcript_end() == 1 && get_w2w() == 0"
_CSBUFLO_EARLY_NOT_ONLOAD_CONDITION = "local_onload_flag != 1"
_CSBUFLO_EARLY_START_CONDITION = "get_st_idle_start() == 0"
_CSBUFLO_EARLY_BUFFERED_CONDITION = "outbuf_len > 0"
_CSBUFLO_EARLY_QUIET_CONDITION = "now_usecs - get_st_idle_start() >= 2000000"


def csbuflo_author_golden_projection() -> dict[str, object]:
    """Project author observations with only the independent Python oracle."""

    real_bytes = 1_000
    junk_bytes = 1_100
    exact_real_bytes = 1_000
    exact_junk_bytes = 1_048
    packet = CSBUFLO_WPES14_PARAMETERS.write_size_bytes

    def source_terminal(output: int, target: int, total: int, *, server: bool) -> bool:
        return (
            output <= (32 if server else 0) and target + packet > total and total + packet > target
        )

    def source_early_transition(
        *,
        transcript_end: bool,
        queued_bytes: int,
        onload: bool,
        idle_start_us: int,
        now_us: int,
        output_bytes: int,
    ) -> tuple[int, int]:
        mode = 1
        resulting_idle_start = idle_start_us
        if transcript_end and queued_bytes == 0:
            if onload:
                mode = -1
            elif idle_start_us == 0:
                resulting_idle_start = now_us
            elif output_bytes > 0:
                mode = 0
            elif now_us - idle_start_us >= CSBUFLO_QUIET_TIME_US:
                mode = -1
        return mode, resulting_idle_start

    early_vectors = {
        "no_transcript": source_early_transition(
            transcript_end=False,
            queued_bytes=0,
            onload=False,
            idle_start_us=1,
            now_us=2_000_001,
            output_bytes=0,
        ),
        "queued_write": source_early_transition(
            transcript_end=True,
            queued_bytes=1,
            onload=True,
            idle_start_us=1,
            now_us=2_000_001,
            output_bytes=0,
        ),
        "onload": source_early_transition(
            transcript_end=True,
            queued_bytes=0,
            onload=True,
            idle_start_us=1,
            now_us=2_000_001,
            output_bytes=0,
        ),
        "idle_start": source_early_transition(
            transcript_end=True,
            queued_bytes=0,
            onload=False,
            idle_start_us=0,
            now_us=5_000_000,
            output_bytes=0,
        ),
        "buffered": source_early_transition(
            transcript_end=True,
            queued_bytes=0,
            onload=False,
            idle_start_us=1_000_000,
            now_us=2_999_999,
            output_bytes=1,
        ),
        "quiet_before": source_early_transition(
            transcript_end=True,
            queued_bytes=0,
            onload=False,
            idle_start_us=1_000_000,
            now_us=2_999_999,
            output_bytes=0,
        ),
        "quiet_boundary": source_early_transition(
            transcript_end=True,
            queued_bytes=0,
            onload=False,
            idle_start_us=1_000_000,
            now_us=3_000_000,
            output_bytes=0,
        ),
    }

    return {
        "estimator": {
            "clamped": 32_768,
            "empty": 32_768,
            "empty_next_boundary": 32_768,
            "pre_boundary": 8_192,
            "pre_boundary_next_boundary": 16_384,
            "upper_median": 8_192,
        },
        "early_termination": {
            "client_buffered_mode": early_vectors["buffered"][0],
            "client_idle_start_mode": early_vectors["idle_start"][0],
            "client_idle_start_us": early_vectors["idle_start"][1],
            "client_no_transcript_mode": early_vectors["no_transcript"][0],
            "client_onload_mode": early_vectors["onload"][0],
            "client_queued_write_mode": early_vectors["queued_write"][0],
            "client_quiet_before_mode": early_vectors["quiet_before"][0],
            "client_quiet_boundary_mode": early_vectors["quiet_boundary"][0],
            "server_buffered_mode": early_vectors["buffered"][0],
            "server_onload_mode": early_vectors["onload"][0],
            "server_quiet_boundary_mode": early_vectors["quiet_boundary"][0],
        },
        "jitter": {
            "raw_0": 0,
            "raw_1": 8_192 // 100,
            "raw_100": 8_192,
            "raw_200": 16_384,
            "raw_201_modulo": 0,
            "stmode_fixed": 8_192,
        },
        "padding": {
            "client_payload_0_0": 0,
            "client_payload_1000_1100": csbuflo_padding_target_bytes(
                real_bytes, junk_bytes, CsBufloPadding.PAYLOAD
            ),
            "client_payload_1000_1048": csbuflo_padding_target_bytes(
                exact_real_bytes, exact_junk_bytes, CsBufloPadding.PAYLOAD
            ),
            "server_payload_1000_1100": csbuflo_padding_target_bytes(
                real_bytes, junk_bytes, CsBufloPadding.PAYLOAD
            ),
            "client_total_0_0": 0,
            "client_total_1000_1100": csbuflo_padding_target_bytes(
                real_bytes, junk_bytes, CsBufloPadding.TOTAL
            ),
            "client_total_1000_1048": csbuflo_padding_target_bytes(
                exact_real_bytes, exact_junk_bytes, CsBufloPadding.TOTAL
            ),
            "server_total_1000_1100": csbuflo_padding_target_bytes(
                real_bytes, junk_bytes, CsBufloPadding.TOTAL
            ),
        },
        "padding_done": {"after_set": 1, "after_unset": 0, "initial": 0},
        "quiet": {"buffered_resets_idle": 0, "onload_idle": 1, "quiet_after": 1, "quiet_before": 0},
        "termination": {
            "client_buffered_mode": -1 if source_terminal(1, 3_072, 2_525, server=False) else 0,
            "client_complete_mode": -1 if source_terminal(0, 3_072, 2_525, server=False) else 0,
            "client_exact_tolerance_mode": (
                -1 if source_terminal(0, 3_072, 2_524, server=False) else 0
            ),
            "server_buffered_mode": -1 if source_terminal(33, 3_072, 2_525, server=True) else 0,
            "server_buffered_padding_done": (
                0 if source_terminal(33, 3_072, 2_525, server=True) else 1
            ),
            "server_complete_mode": -1 if source_terminal(32, 3_072, 2_525, server=True) else 0,
            "server_complete_padding_done": (
                0 if source_terminal(32, 3_072, 2_525, server=True) else 1
            ),
        },
    }


def _source_match_once(pattern: str, source: str, label: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, source, flags=re.MULTILINE))
    if len(matches) != 1:
        raise ValueError(f"CS-BuFLO source extractor expected one {label}, found {len(matches)}")
    return matches[0]


def _balanced_source_at(source: str, start: int, label: str) -> str:
    opening = source.find("{", start)
    if opening < 0:
        raise ValueError(f"CS-BuFLO source extractor found no opening brace for {label}")
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if character == "\n":
                state = "code"
        elif state == "block-comment":
            if character == "*" and following == "/":
                state = "code"
                index += 1
        elif state in {"string", "character"}:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif (state == "string" and character == '"') or (
                state == "character" and character == "'"
            ):
                state = "code"
        elif character == "/" and following == "/":
            state = "line-comment"
            index += 1
        elif character == "/" and following == "*":
            state = "block-comment"
            index += 1
        elif character == '"':
            state = "string"
        elif character == "'":
            state = "character"
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
        index += 1
    raise ValueError(f"CS-BuFLO source extractor found no closing brace for {label}")


def _balanced_source_statement(source: str, marker: str, label: str) -> str:
    """Extract one C statement without interpreting its implementation."""

    if source.count(marker) != 1:
        raise ValueError(
            f"CS-BuFLO source extractor expected one {label}, found {source.count(marker)}"
        )
    return _balanced_source_at(source, source.index(marker), label)


def _source_if_else(source: str, marker: str, label: str) -> str:
    first = _balanced_source_statement(source, marker, f"{label} if branch")
    start = source.index(marker)
    after_first = start + len(first)
    alternate = re.match(r"\s*else\s*\{", source[after_first:])
    if alternate is None:
        raise ValueError(f"CS-BuFLO source extractor found no else branch for {label}")
    else_start = after_first + alternate.start() + alternate.group(0).index("else")
    second = _balanced_source_at(source, else_start, f"{label} else branch")
    return source[start : else_start + len(second)]


def _source_line_once(source: str, statement: str, label: str) -> str:
    matches = [line.strip() for line in source.splitlines() if line.strip() == statement]
    if len(matches) != 1:
        raise ValueError(f"CS-BuFLO source extractor expected one {label}, found {len(matches)}")
    return matches[0]


def _source_line_count(source: str, statement: str, count: int, label: str) -> str:
    matches = [line.strip() for line in source.splitlines() if line.strip() == statement]
    if len(matches) != count:
        raise ValueError(
            f"CS-BuFLO source extractor expected {count} {label} entries, found {len(matches)}"
        )
    return statement


def _extract_csbuflo_source_slices(
    *,
    misc_header: Path,
    packet: Path,
    clientloop: Path,
    serverloop: Path,
) -> tuple[str, dict[str, object]]:
    """Create an ephemeral executable from exact, hash-pinned author slices.

    The historical OpenSSH event loops require a bilateral network runtime and
    obsolete cryptographic ABI.  The isolated gate therefore compiles only
    deterministic source slices after the complete input files pass their
    immutable hashes.  No extracted source is written into the repository or
    linked into a collection image.
    """

    header_source = misc_header.read_text(encoding="utf-8")
    packet_source = packet.read_text(encoding="utf-8")
    client_source = clientloop.read_text(encoding="utf-8")
    server_source = serverloop.read_text(encoding="utf-8")

    target_define = _source_match_once(
        r"^#define[ \t]+TARGET_QUEUE_LEN[ \t]+548(?:[ \t].*)?$",
        header_source,
        "TARGET_QUEUE_LEN definition",
    ).group(0)
    padding_done_define = _source_match_once(
        r"^#define[ \t]+PADDINGDONE[ \t]+1[ \t]*$",
        client_source,
        "client PADDINGDONE definition",
    ).group(0)
    jitter_function = _balanced_source_statement(
        packet_source,
        "unsigned long long update_time(unsigned long long now, long tau){",
        "packet jitter function",
    )
    client_payload = _source_if_else(
        client_source,
        "if(total_sent_bytes == 0){",
        "client payload-padding expression",
    )
    server_payload = _source_if_else(
        server_source,
        "if(total_sent_bytes == 0){",
        "server payload-padding expression",
    )
    total_pattern = (
        r"^[ \t]*//[ \t]*(?P<statement>target_sent_bytes = total_sent_bytes == 0 \? 0 : "
        r"\(long\)pow\(2, ceil\(log2\(total_sent_bytes/1\.0\)\)\);)[ \t]*$"
    )
    client_total = _source_match_once(
        total_pattern, client_source, "client inactive total-padding expression"
    ).group("statement")
    server_total = _source_match_once(
        total_pattern, server_source, "server inactive total-padding expression"
    ).group("statement")

    client_terminal_marker = f"if({_CSBUFLO_CLIENT_TERMINAL_CONDITION}){{"
    server_terminal_marker = f"if({_CSBUFLO_SERVER_TERMINAL_CONDITION}){{"
    client_terminal = _balanced_source_statement(
        client_source, client_terminal_marker, "client terminal branch"
    )
    server_terminal = _balanced_source_statement(
        server_source, server_terminal_marker, "server terminal branch"
    )
    early_marker = f"if({_CSBUFLO_EARLY_OUTER_CONDITION}){{"
    client_early = _balanced_source_statement(
        client_source, early_marker, "client early-termination branch"
    )
    server_early = _balanced_source_statement(
        server_source, early_marker, "server early-termination branch"
    )
    for branch, endpoint in ((client_early, "client"), (server_early, "server")):
        for condition, label in (
            (_CSBUFLO_EARLY_NOT_ONLOAD_CONDITION, "not-onLoad condition"),
            (_CSBUFLO_EARLY_START_CONDITION, "idle-start condition"),
            (_CSBUFLO_EARLY_BUFFERED_CONDITION, "buffered fallback condition"),
            (_CSBUFLO_EARLY_QUIET_CONDITION, "quiet-boundary condition"),
        ):
            _source_match_once(
                rf"if\({re.escape(condition)}\)\{{",
                branch,
                f"{endpoint} early-termination {label}",
            )
    early_idle_action = _source_line_once(
        client_early, "set_st_idle_start(now_usecs);", "client early idle-start transition"
    )
    _source_line_once(
        server_early, "set_st_idle_start(now_usecs);", "server early idle-start transition"
    )
    early_shape_action = _source_line_once(
        client_early, "set_stmode(0);", "client early shaping transition"
    )
    _source_line_once(server_early, "set_stmode(0);", "server early shaping transition")
    early_exit_action = _source_line_count(
        client_early, "set_stmode(-1);", 2, "client early exit transition"
    )
    _source_line_count(server_early, "set_stmode(-1);", 2, "server early exit transition")
    client_mode_action = _source_line_once(
        client_terminal, "set_stmode(-1);", "client terminal mode transition"
    )
    client_notify_action = _source_line_once(
        client_terminal, "packet_send_notify(4,'p');", "client padding-done notification"
    )
    _source_match_once(
        r"if\(PADDINGDONE == 1\)\{\s*packet_send_notify\(4,'p'\);\s*packet_send\(\);\s*\}",
        client_terminal,
        "client enabled padding-done notification branch",
    )
    server_padding_action = _source_line_once(
        server_terminal, "unset_paddingdone_flag();", "server padding-done reset"
    )
    server_mode_action = _source_line_once(
        server_terminal, "set_stmode(-1);", "server terminal mode transition"
    )
    for pattern, label in (
        (
            r"case[ \t]+SSH2_MSG_NOTIFY_PADDINGDONE:\s*set_paddingdone_flag\(\);",
            "SSH2 padding-done dispatch",
        ),
        (
            r"case[ \t]+SSH_MSG_NOTIFY_PADDINGDONE:\s*set_paddingdone_flag\(\);",
            "SSH1 padding-done dispatch",
        ),
    ):
        _source_match_once(pattern, packet_source, label)
    active_padding_done_consumers = sum(
        source.count("get_paddingdone_flag(")
        for source in (client_source, server_source, packet_source)
    )
    if active_padding_done_consumers != 0:
        raise ValueError("CS-BuFLO pinned padding-done consumer inventory changed")

    source_segments = {
        "client_early_termination_branch": client_early,
        "client_padding_done_define": padding_done_define,
        "client_padding_done_notification": client_notify_action,
        "client_payload_padding": client_payload,
        "client_terminal_branch": client_terminal,
        "client_total_padding_inactive": client_total,
        "jitter_function": jitter_function,
        "server_early_termination_branch": server_early,
        "server_payload_padding": server_payload,
        "server_terminal_branch": server_terminal,
        "server_total_padding_inactive": server_total,
        "target_queue_define": target_define,
    }
    segment_hashes = {
        name: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for name, value in sorted(source_segments.items())
    }

    generated = "\n".join(
        (
            "/* Ephemeral exact-source executable; never installed or retained. */",
            "#include <math.h>",
            "#include <stdint.h>",
            "#include <stdlib.h>",
            "uint32_t arc4random(void);",
            "int get_stmode(void);",
            "void set_stmode(int mode);",
            "void set_w2w(long value);",
            "long get_w2w(void);",
            "int get_onload_flag(void);",
            "void set_onload_flag(void);",
            "void unset_onload_flag(void);",
            "int get_transcript_end(void);",
            "void set_transcript_end(void);",
            "void unset_transcript_end(void);",
            "unsigned long long get_st_idle_start(void);",
            "void set_st_idle_start(unsigned long long value);",
            "int get_paddingdone_flag(void);",
            "void set_paddingdone_flag(void);",
            "void unset_paddingdone_flag(void);",
            target_define,
            "#define update_time qcsd_author_update_time",
            jitter_function,
            "#undef update_time",
            (
                "long qcsd_author_client_payload_target(long total_sent_bytes, "
                "long cur_total_realincoming_bytes, int outbuf_len) {"
            ),
            "long target_sent_bytes = -1; long base = 0;",
            client_payload,
            "return target_sent_bytes;",
            "}",
            (
                "long qcsd_author_server_payload_target(long total_sent_bytes, "
                "long cur_total_realincoming_bytes, int outbuf_len) {"
            ),
            "long target_sent_bytes = -1; long base = 0;",
            server_payload,
            "return target_sent_bytes;",
            "}",
            "long qcsd_author_client_total_target(long total_sent_bytes) {",
            "long target_sent_bytes = -1;",
            client_total,
            "return target_sent_bytes;",
            "}",
            "long qcsd_author_server_total_target(long total_sent_bytes) {",
            "long target_sent_bytes = -1;",
            server_total,
            "return target_sent_bytes;",
            "}",
            (
                "int qcsd_author_early_transition(int transcript_end, long queued_bytes, "
                "int onload, unsigned long long idle_start, unsigned long long now_usecs, "
                "int outbuf_len, unsigned long long *result_idle_start) {"
            ),
            "int local_onload_flag;",
            "set_stmode(1); set_w2w(queued_bytes); set_st_idle_start(idle_start);",
            "if(transcript_end) { set_transcript_end(); } else { unset_transcript_end(); }",
            "if(onload) { set_onload_flag(); } else { unset_onload_flag(); }",
            "local_onload_flag = get_onload_flag();",
            f"if({_CSBUFLO_EARLY_OUTER_CONDITION}) {{",
            f"if({_CSBUFLO_EARLY_NOT_ONLOAD_CONDITION}) {{",
            f"if({_CSBUFLO_EARLY_START_CONDITION}) {{",
            early_idle_action,
            "} else {",
            f"if({_CSBUFLO_EARLY_BUFFERED_CONDITION}) {{",
            early_shape_action,
            "} else {",
            f"if({_CSBUFLO_EARLY_QUIET_CONDITION}) {{",
            early_exit_action,
            "}",
            "}",
            "}",
            "} else {",
            early_exit_action,
            "}",
            "}",
            "*result_idle_start = get_st_idle_start();",
            "return get_stmode();",
            "}",
            (
                "int qcsd_author_client_transition(int outbuf_len, long target_sent_bytes, "
                "long total_sent_bytes) {"
            ),
            "set_stmode(0);",
            f"if({_CSBUFLO_CLIENT_TERMINAL_CONDITION}) {{",
            client_mode_action,
            "}",
            "return get_stmode();",
            "}",
            (
                "int qcsd_author_server_transition(int outbuf_len, long target_sent_bytes, "
                "long total_sent_bytes, int *padding_done) {"
            ),
            "set_stmode(0); set_paddingdone_flag();",
            f"if({_CSBUFLO_SERVER_TERMINAL_CONDITION}) {{",
            server_padding_action,
            server_mode_action,
            "}",
            "*padding_done = get_paddingdone_flag();",
            "return get_stmode();",
            "}",
            "",
        )
    )
    return generated, {
        "active_padding_profile": "CPSP-payload-at-both-endpoints",
        "client_padding_done_notification": "active-p",
        "early_termination_quiet_comparison": "inclusive-elapsed-us>=2000000",
        "early_termination_source_state_machine_executed": True,
        "full_network_loop_executed": False,
        "full_network_loop_status": (
            "not-executed-requires-historical-bilateral-openssh-runtime-and-obsolete-crypto-abi"
        ),
        "jitter_source_function_executed": True,
        "paper_algorithm4_power_crossing_validation": (
            "independent-oracle-only-no-distinct-exported-author-helper"
        ),
        "padding_done_active_consumer_count": active_padding_done_consumers,
        "padding_done_dispatch_paths_verified": ["SSH1", "SSH2"],
        "padding_done_flag_author_object_executed": True,
        "payload_padding_source_executed": True,
        "quiet_function_author_object_executed": True,
        "segment_sha256": segment_hashes,
        "server_padding_done_reset_executed": True,
        "source_slice_transforms": [
            "preprocessor-only-function-name-alias",
            "clean-room-parameter-and-state-scaffolding",
            "comment-prefix-removal-for-inactive-total-expression",
        ],
        "termination_predicates_and_state_actions_executed": True,
        "total_padding_active_in_pinned_runtime": False,
        "total_padding_source_expression_executed": True,
    }


def _csbuflo_harness_source() -> Path:
    configured = os.environ.get("QCSD_CSBUFLO_AUTHOR_HARNESS_SOURCE")
    candidates = [
        Path(configured) if configured else None,
        LAB_ROOT / "tools/qcsd_csbuflo_author_harness.c",
        Path("/usr/local/share/qcsd-lab/qcsd_csbuflo_author_harness.c"),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file() and not candidate.is_symlink():
            return candidate.resolve()
    raise ValueError("clean-room CS-BuFLO author harness source is unavailable")


def _run_reference_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        errors = completed.stderr.strip().splitlines()
        detail = errors[-1] if errors else f"exit {completed.returncode}"
        raise ValueError(f"isolated CS-BuFLO author build failed for {command[0]}: {detail}")
    return completed


def _run_csbuflo_author_gate(
    *,
    misc_path: Path,
    misc_header_path: Path,
    packet_path: Path,
    clientloop_path: Path,
    serverloop_path: Path,
) -> dict[str, object]:
    """Execute deterministic vectors against pinned author objects and slices."""

    misc = misc_path.resolve()
    source_root = misc.parent
    if misc != source_root / "misc.c":
        raise ValueError("CS-BuFLO misc.c does not preserve the pinned repository layout")
    expected_paths = {
        misc_header_path.resolve(): source_root / "misc.h",
        packet_path.resolve(): source_root / "packet.c",
        clientloop_path.resolve(): source_root / "clientloop.c",
        serverloop_path.resolve(): source_root / "serverloop.c",
    }
    if any(actual != expected for actual, expected in expected_paths.items()):
        raise ValueError("CS-BuFLO source slices do not preserve the pinned repository layout")
    generated_source, extraction_manifest = _extract_csbuflo_source_slices(
        misc_header=misc_header_path,
        packet=packet_path,
        clientloop=clientloop_path,
        serverloop=serverloop_path,
    )
    harness = _csbuflo_harness_source()
    auxiliary_root = Path("/usr/share/autoconf/build-aux")
    if not all((auxiliary_root / name).is_file() for name in ("config.guess", "config.sub")):
        raise ValueError("modern autoconf config.guess/config.sub are unavailable")

    with tempfile.TemporaryDirectory(prefix="qcsd-csbuflo-author-") as temporary:
        work = Path(temporary) / "modified_openssh-5.9p1"
        shutil.copytree(
            source_root,
            work,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "*.o"),
        )
        for name in ("config.guess", "config.sub"):
            shutil.copy2(auxiliary_root / name, work / name)
        _run_reference_command(("autoheader",), cwd=work)
        _run_reference_command(("autoconf",), cwd=work)
        _run_reference_command(
            (
                "./configure",
                "--without-openssl-header-check",
                "--without-zlib-version-check",
            ),
            cwd=work,
        )
        _run_reference_command(("make", "misc.o"), cwd=work)
        extracted_source = Path(temporary) / "csbuflo-author-slices.c"
        extracted_source.write_text(generated_source, encoding="utf-8")
        extracted_object = Path(temporary) / "csbuflo-author-slices.o"
        executable = Path(temporary) / "csbuflo-author-golden"
        compiler = os.environ.get("CC", "cc")
        _run_reference_command(
            (
                compiler,
                "-O2",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                os.fspath(extracted_source),
                "-o",
                os.fspath(extracted_object),
            ),
            cwd=work,
        )
        _run_reference_command(
            (
                compiler,
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                os.fspath(harness),
                os.fspath(extracted_object),
                os.fspath(work / "misc.o"),
                "-lm",
                "-o",
                os.fspath(executable),
            ),
            cwd=work,
        )
        completed = _run_reference_command((os.fspath(executable),), cwd=work, timeout=30)
        try:
            observed = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ValueError("isolated CS-BuFLO author harness returned invalid JSON") from error
        expected = csbuflo_author_golden_projection()
        if observed != expected:
            raise ValueError("CS-BuFLO author/source-slice conformance mismatch")
        normalized_objects: dict[str, Path] = {}
        for name, source_object in {
            "misc": work / "misc.o",
            "source_slices": extracted_object,
        }.items():
            normalized = Path(temporary) / f"{name}.normalized.o"
            _run_reference_command(
                (
                    "objcopy",
                    "--strip-debug",
                    "--remove-section=.comment",
                    os.fspath(source_object),
                    os.fspath(normalized),
                ),
                cwd=work,
            )
            normalized_objects[name] = normalized
        compiler_version = _run_reference_command((compiler, "--version"), cwd=work).stdout
        return {
            "author_object_normalization": "objcopy --strip-debug --remove-section=.comment",
            "author_object_sha256": sha256_file(normalized_objects["misc"]),
            "author_source_slice_object_sha256": sha256_file(normalized_objects["source_slices"]),
            "compiler": compiler_version.splitlines()[0],
            "golden_vectors": observed,
            "harness_sha256": sha256_file(harness),
            "independent_oracle_match": True,
            "source_extraction": extraction_manifest,
            "source_extraction_input_sha256": _canonical_digest(
                extraction_manifest["segment_sha256"]
            ),
            "source_slice_translation_sha256": hashlib.sha256(
                generated_source.encode("utf-8")
            ).hexdigest(),
            "source_match": True,
            "source_prose_discrepancy": (
                "empty author window selects upper rho; paper Algorithm 2 retains current rho"
            ),
            "source_prose_discrepancies": [
                "empty author window selects upper rho; paper Algorithm 2 retains current rho",
                (
                    "pinned clientloop/serverloop actively implement CPSP; CTSP survives only as "
                    "a commented source expression"
                ),
                (
                    "the pinned padding-done flag has SSH1/SSH2 setters and resetters but no "
                    "active get_paddingdone_flag consumer in clientloop/serverloop/packet"
                ),
                (
                    "pinned early termination is a transcript-end/zero-w2w state machine; the "
                    "paper Algorithm 4 power-of-two predicate remains an independent oracle"
                ),
                (
                    "pinned early-termination quiet exit is inclusive at 2000000 us while "
                    "misc.c channel_idle uses a strict greater-than comparison"
                ),
            ],
        }


def _gate_receipt_value(
    *,
    validated_sources: list[dict[str, str]],
    profile_rows: list[dict[str, object]],
    source_projection_sha256: str,
    csbuflo_author: dict[str, object],
    archive: ArchiveRatioAudit,
) -> dict[str, object]:
    reference_root = _reference_root()
    references = []
    for reference_id in (BUFLO_REFERENCE_ID, CSBUFLO_REFERENCE_ID):
        reference = reference_root / f"{reference_id}.json"
        validation = validate_reference_receipt(reference)
        references.append(
            {
                "reference_id": reference_id,
                "reference_sha256": validation.reference_sha256,
                "receipt_sha256": validation.receipt_sha256,
            }
        )
    expected = CSBUFLO_CPSP_ARCHIVE_REFERENCE
    return {
        "artifact_type": "qcsd-buflo-csbuflo-conformance-receipt",
        "buflo_author_conformance": {
            "golden_input_sha256": _canonical_digest(
                [
                    [packet.monotonic_ms, packet.direction, packet.length_bytes]
                    for packet in _BUFLO_GATE_PACKETS
                ]
            ),
            "live_order": list(_LIVE_DIRECTIONS),
            "paper_bidirectional_order": "unspecified-independent-endpoints",
            "profiles": profile_rows,
            "source_order": list(_SOURCE_DIRECTIONS),
            "source_projection_sha256": source_projection_sha256,
        },
        "clean_room": True,
        "csbuflo_archive_conformance": {
            "bandwidth_ratio": archive.bandwidth_ratio,
            "baseline_bytes": archive.baseline_bytes,
            "defended_bytes": archive.defended_bytes,
            "excluded_defended_bytes": archive.excluded_defended_bytes,
            "included_records": archive.included_records,
            "padding_profile": expected.padding_profile,
            "source_id": expected.source_id,
            "total_records": archive.total_records,
            "zero_baseline_records": archive.zero_baseline_records,
        },
        "csbuflo_author_conformance": csbuflo_author,
        "csbuflo_estimator_contract": {
            "adaptation_counter": "per-direction-actually-transmitted-real-plus-junk-bytes",
            "direction_windows": list(_LIVE_DIRECTIONS),
            "first_boundary_bytes": CSBUFLO_WPES14_PARAMETERS.first_adaptation_boundary_bytes,
            "max_samples_per_direction": CSBUFLO_WPES14_PARAMETERS.max_rate_samples,
            "next_boundary_rule": "double-after-each-adaptation",
            "rate_quantization": _CSBUFLO_RATE_QUANTIZATION_DISCREPANCY["resolved_rule"],
            "rate_quantization_resolution": "paper-Algorithm-2-floor-formula",
        },
        "csbuflo_paper_internal_discrepancies": [
            dict(_CSBUFLO_RATE_QUANTIZATION_DISCREPANCY)
        ],
        "external_sources": validated_sources,
        "passed": True,
        "reference_documents": references,
        "schema_version": 1,
    }


def run_reference_gate(
    external_root_or_bindings: Path | Mapping[str, Path],
    output_receipt: Path,
) -> ReferenceGateResult:
    """Run the pinned external conformance gate and create one receipt.

    All checks finish before the output is opened.  The author implementation
    runs only in an isolated Python subprocess; it is never imported into the
    QCSD process, copied into the repository, or used by ordinary unit tests.
    The output uses exclusive creation and is never overwritten.
    """

    output = Path(output_receipt)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"reference gate receipt already exists: {output}")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError(f"reference gate receipt parent is invalid: {output.parent}")

    bindings = _resolve_gate_bindings(external_root_or_bindings)
    validated_sources = _validate_gate_bindings(bindings)
    profile_rows, source_projection_sha256 = _run_buflo_author_gate(
        Path(bindings["dyer-folklore-py"])
    )
    csbuflo_author = _run_csbuflo_author_gate(
        misc_path=Path(bindings["csbuflo-misc-c"]),
        misc_header_path=Path(bindings["csbuflo-misc-h"]),
        packet_path=Path(bindings["csbuflo-packet-c"]),
        clientloop_path=Path(bindings["csbuflo-clientloop-c"]),
        serverloop_path=Path(bindings["csbuflo-serverloop-c"]),
    )
    archive = audit_csbuflo_archive(Path(bindings["csbuflo-cpsp-trace-archive"]))
    expected = CSBUFLO_CPSP_ARCHIVE_REFERENCE
    observed_archive = (
        archive.total_records,
        archive.included_records,
        archive.zero_baseline_records,
        archive.defended_bytes,
        archive.baseline_bytes,
    )
    expected_archive = (
        expected.total_records,
        expected.included_records,
        expected.zero_baseline_records,
        expected.defended_bytes,
        expected.baseline_bytes,
    )
    if observed_archive != expected_archive or not math.isclose(
        archive.bandwidth_ratio,
        expected.bandwidth_ratio,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError("CS-BuFLO archive conformance mismatch")

    receipt_value = _gate_receipt_value(
        validated_sources=validated_sources,
        profile_rows=profile_rows,
        source_projection_sha256=source_projection_sha256,
        csbuflo_author=csbuflo_author,
        archive=archive,
    )
    encoded = json.dumps(receipt_value, indent=2, sort_keys=True) + "\n"
    with output.open("x", encoding="utf-8") as destination:
        destination.write(encoded)
        destination.flush()
        os.fsync(destination.fileno())
    return ReferenceGateResult(
        output.resolve(),
        sha256_file(output),
        len(profile_rows),
        archive,
    )


def reference_document_json(reference_id: str) -> str:
    """Serialize one canonical document exactly as checked into ``config/reference``."""

    if reference_id == BUFLO_REFERENCE_ID:
        value = buflo_reference_document()
    elif reference_id == CSBUFLO_REFERENCE_ID:
        value = csbuflo_reference_document()
    else:
        raise ValueError(f"unknown reference id: {reference_id}")
    return json.dumps(value, indent=2, sort_keys=True) + "\n"
