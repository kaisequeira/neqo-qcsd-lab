"""Deterministic corpus-wide WTF-PAD histogram fitting."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .fitting_trace import FittingTrace


GENERATED_BY = "qcsd_lab.fitting_wtfpad 2.0.0"
WINDOW_PACKETS = 2
TOTAL_BINS = 20
FINITE_BINS = 19
TUNING_PERCENTILE = 0.5
FINITE_DOMAIN_PERCENTILE = 99.5
FINITE_TOKENS = 10_000
MIN_STATE_POPULATION = 20
FAKE_BURST_PROBABILITY = 0.9
MAX_U32 = 2**32 - 1
MAX_U64 = 2**64 - 1
BURST_INFINITY_FORMULA = "k_inf = (1 - p_fake) / p_fake * K"
GAP_INFINITY_FORMULA = "k_inf = (K - mean_burst_length + 1) / (mean_burst_length - 1)"
BURST_TRANSFORMATION = "paper-gaussian-percentile-shift-v1"
IDENTITY_TRANSFORMATION = "identity"


@dataclass(frozen=True)
class ModelCandidate:
    name: str
    parameters: tuple[float, ...]
    ks_statistic: float


def fit_wtf_pad(
    traces: Sequence[FittingTrace], *, fitted_from: str
) -> tuple[dict[str, object], dict[str, object]]:
    """Fit one pooled bandwidth threshold and two direction-specific state models."""

    if not traces:
        raise ValueError("WTF-PAD fitting requires at least one training trace")
    if not fitted_from.strip():
        raise ValueError("WTF-PAD fitted_from identity must not be empty")
    threshold = corpus_mean_bandwidth(traces)
    training_samples: list[dict[str, object]] = []
    populations: dict[str, dict[str, list[int]]] = {
        direction: {"intra": [], "between": [], "burst_lengths": []}
        for direction in ("outgoing", "incoming")
    }
    for trace in traces:
        total_bytes, active_duration_ns = _trace_bandwidth_values(trace)
        directions: dict[str, object] = {}
        for direction in ("outgoing", "incoming"):
            intra, between, burst_lengths = _trace_direction_populations(
                trace, direction, threshold=threshold
            )
            populations[direction]["intra"].extend(intra)
            populations[direction]["between"].extend(between)
            populations[direction]["burst_lengths"].extend(burst_lengths)
            directions[direction] = {
                "intra_burst_delays_us": intra,
                "between_burst_delays_us": between,
                "burst_lengths_packets": burst_lengths,
            }
        training_samples.append(
            {
                "training_input_sha256": trace.training_input_sha256,
                "total_bytes": total_bytes,
                "active_duration_ns": active_duration_ns,
                "directions": directions,
            }
        )
    directions: dict[str, object] = {}
    population_receipt: dict[str, object] = {}
    for direction in ("outgoing", "incoming"):
        intra = np.asarray(populations[direction]["intra"], dtype=np.int64)
        between = np.asarray(populations[direction]["between"], dtype=np.int64)
        burst_lengths = np.asarray(populations[direction]["burst_lengths"], dtype=np.int64)
        if not len(burst_lengths):
            raise ValueError(f"WTF-PAD cannot estimate {direction} mean burst length")
        mean_length = _float(float(np.mean(burst_lengths)))
        if not math.isfinite(mean_length) or mean_length <= 1.0:
            raise ValueError(f"WTF-PAD {direction} mean burst length must exceed one")
        burst_infinity = _rounded_positive_tokens(
            ((1.0 - FAKE_BURST_PROBABILITY) / FAKE_BURST_PROBABILITY) * FINITE_TOKENS,
            f"{direction} H_B",
        )
        gap_infinity = _rounded_positive_tokens(
            (FINITE_TOKENS - mean_length + 1.0) / (mean_length - 1.0),
            f"{direction} H_G",
        )
        burst_histogram, burst_fit = _fit_population(
            between,
            infinity_tokens=burst_infinity,
            label=f"{direction} between-burst",
            tuning_percentile=TUNING_PERCENTILE,
        )
        gap_histogram, gap_fit = _fit_population(
            intra,
            infinity_tokens=gap_infinity,
            label=f"{direction} intra-burst",
            tuning_percentile=None,
        )
        directions[direction] = {
            "burst": burst_histogram,
            "gap": gap_histogram,
            "fit": {
                "mean_burst_length_packets": _float(mean_length),
                "burst": burst_fit,
                "gap": gap_fit,
            },
        }
        population_receipt[direction] = {
            "between_burst_delays": len(between),
            "intra_burst_delays": len(intra),
            "bursts": len(burst_lengths),
        }

    fitting = {
        "instantaneous_bandwidth_window_packets": WINDOW_PACKETS,
        "burst_threshold_method": "corpus-mean-bandwidth",
        "bandwidth_threshold_bytes_per_second": _float(threshold),
        "candidate_models": ["normal", "lognormal"],
        "tuning_percentile": TUNING_PERCENTILE,
        "tuning_applies_to": "burst-histogram-only",
        "tuning_transformation": BURST_TRANSFORMATION,
        "finite_domain_percentile": FINITE_DOMAIN_PERCENTILE,
        "histogram_bin_count": TOTAL_BINS,
        "histogram_scale": "exponential",
        "finite_token_budget": FINITE_TOKENS,
        "fake_burst_probability": FAKE_BURST_PROBABILITY,
        "infinity_token_formulas": {
            "burst": BURST_INFINITY_FORMULA,
            "gap": GAP_INFINITY_FORMULA,
        },
    }
    artifact: dict[str, object] = {
        "schema_version": 2,
        "adaptation": "qcsd-client-only",
        "paper_equivalent": False,
        "fitted_from": fitted_from,
        "generated_by": GENERATED_BY,
        "fitting": fitting,
        "outgoing": directions["outgoing"],
        "incoming": directions["incoming"],
    }
    diagnostics: dict[str, object] = {
        "algorithm": "corpus-mean-bandwidth-mle-ks-histograms",
        "global_bandwidth_threshold_bytes_per_second": _float(threshold),
        "populations": population_receipt,
        "training_samples": training_samples,
    }
    return artifact, diagnostics


def corpus_mean_bandwidth(traces: Sequence[FittingTrace]) -> float:
    total_bytes = 0
    total_duration_ns = 0
    for trace in traces:
        trace_bytes, trace_duration_ns = _trace_bandwidth_values(trace)
        total_bytes += trace_bytes
        total_duration_ns += trace_duration_ns
    if total_duration_ns <= 0 or total_bytes <= 0:
        raise ValueError("WTF-PAD corpus has no positive-duration packet trace")
    return total_bytes * 1_000_000_000.0 / total_duration_ns


def _trace_bandwidth_values(trace: FittingTrace) -> tuple[int, int]:
    packets = trace.packets
    if len(packets) < WINDOW_PACKETS:
        raise ValueError(f"WTF-PAD trace {trace.sample_id} has fewer than two natural datagrams")
    duration_ns = packets[-1].monotonic_ns - packets[0].monotonic_ns
    if duration_ns <= 0:
        raise ValueError(f"WTF-PAD trace {trace.sample_id} has no positive active duration")
    return sum(packet.length_bytes for packet in packets), duration_ns


def _direction_populations(
    traces: Sequence[FittingTrace], direction: str, *, threshold: float
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    intra: list[int] = []
    between: list[int] = []
    lengths: list[int] = []
    for trace in traces:
        trace_intra, trace_between, trace_lengths = _trace_direction_populations(
            trace, direction, threshold=threshold
        )
        intra.extend(trace_intra)
        between.extend(trace_between)
        lengths.extend(trace_lengths)
    return (
        np.asarray(intra, dtype=np.int64),
        np.asarray(between, dtype=np.int64),
        np.asarray(lengths, dtype=np.int64),
    )


def _trace_direction_populations(
    trace: FittingTrace, direction: str, *, threshold: float
) -> tuple[list[int], list[int], list[int]]:
    packets = [packet for packet in trace.packets if packet.direction == direction]
    if len(packets) < WINDOW_PACKETS:
        raise ValueError(
            f"WTF-PAD {direction} trace {trace.sample_id} has fewer than two datagrams"
        )
    intra: list[int] = []
    between: list[int] = []
    lengths: list[int] = []
    burst_length = 1
    for left, right in zip(packets, packets[1:]):
        delay_ns = right.monotonic_ns - left.monotonic_ns
        if delay_ns <= 0:
            raise ValueError(
                f"WTF-PAD {direction} trace {trace.sample_id} has a nonpositive inter-arrival"
            )
        delay_us = (delay_ns + 999) // 1_000
        instantaneous = (left.length_bytes + right.length_bytes) * 1_000_000_000.0 / delay_ns
        if instantaneous >= threshold:
            intra.append(delay_us)
            burst_length += 1
        else:
            between.append(delay_us)
            lengths.append(burst_length)
            burst_length = 1
    lengths.append(burst_length)
    return intra, between, lengths


def _fit_population(
    values: np.ndarray,
    *,
    infinity_tokens: int,
    label: str,
    tuning_percentile: float | None,
) -> tuple[dict[str, object], dict[str, object]]:
    delays = np.asarray(values, dtype=np.int64)
    if delays.ndim != 1 or not len(delays) or np.any(delays <= 0):
        raise ValueError(f"WTF-PAD {label} population must contain positive delays")
    if len(np.unique(delays)) < 2:
        raise ValueError(f"WTF-PAD {label} population requires at least two distinct values")
    if len(delays) < MIN_STATE_POPULATION:
        raise ValueError(
            f"WTF-PAD {label} population requires at least {MIN_STATE_POPULATION} delays"
        )
    candidates = _model_candidates(delays)
    selected = _select_candidate(candidates)
    if tuning_percentile is None:
        runtime_parameters = selected.parameters
        transformation = IDENTITY_TRANSFORMATION
    else:
        runtime_parameters = _tuned_parameters(selected, tuning_percentile)
        transformation = BURST_TRANSFORMATION
    distribution = _distribution(selected.name, runtime_parameters)
    fitted_max = float(distribution.ppf(FINITE_DOMAIN_PERCENTILE / 100.0))
    if not math.isfinite(fitted_max) or fitted_max <= 0:
        raise ValueError(f"WTF-PAD {label} model has no positive finite percentile")
    maximum = int(math.ceil(fitted_max))
    edges = _exponential_edges(maximum)
    cdf = np.asarray(distribution.cdf(np.asarray(edges, dtype=float)), dtype=float)
    lower = np.concatenate(([float(distribution.cdf(0.0))], cdf[:-1]))
    tokens = _apportion_tokens(np.maximum(0.0, cdf - lower), FINITE_TOKENS)
    histogram = {
        "edges_us": list(edges),
        "tokens": list(tokens),
        "infinity_tokens": infinity_tokens,
    }
    fit = {
        "sample_count": len(delays),
        "selected_model": selected.name,
        "histogram_max_us": edges[-1],
        "runtime_parameters": [_float(value) for value in runtime_parameters],
        "parameter_transformation": transformation,
        "candidates": [
            {
                "name": candidate.name,
                "parameters": [_float(value) for value in candidate.parameters],
                "ks_statistic": _float(candidate.ks_statistic),
            }
            for candidate in candidates
        ],
    }
    return histogram, fit


def _model_candidates(values: np.ndarray) -> tuple[ModelCandidate, ...]:
    from scipy import stats

    samples = np.asarray(values, dtype=np.float64)
    if len(np.unique(samples)) < 2:
        raise ValueError("WTF-PAD delay populations require at least two distinct values")
    normal_location, normal_scale = stats.norm.fit(samples)
    log_shape, log_location, log_scale = stats.lognorm.fit(samples, floc=0)
    candidates = (
        ModelCandidate(
            "normal",
            (float(normal_location), float(normal_scale)),
            float(stats.kstest(samples, "norm", args=(normal_location, normal_scale)).statistic),
        ),
        ModelCandidate(
            "lognormal",
            (float(log_shape), float(log_location), float(log_scale)),
            float(
                stats.kstest(
                    samples, "lognorm", args=(log_shape, log_location, log_scale)
                ).statistic
            ),
        ),
    )
    for candidate in candidates:
        if not 0 <= candidate.ks_statistic <= 1 or any(
            not math.isfinite(value) for value in candidate.parameters
        ):
            raise ValueError("WTF-PAD maximum-likelihood fit produced an invalid value")
    return candidates


def _select_candidate(candidates: Sequence[ModelCandidate]) -> ModelCandidate:
    """Select minimum KS while preserving the declared normal-first tie order."""

    if not candidates:
        raise ValueError("WTF-PAD model selection requires candidates")
    return min(candidates, key=lambda candidate: candidate.ks_statistic)


def _distribution(name: str, parameters: Sequence[float]):
    from scipy import stats

    if name == "normal":
        return stats.norm(*parameters)
    if name == "lognormal":
        return stats.lognorm(*parameters)
    raise ValueError(f"unsupported WTF-PAD model: {name}")


def _tuned_parameters(candidate: ModelCandidate, percentile: float) -> tuple[float, ...]:
    from scipy import stats

    if not 0 < percentile <= 0.5:
        raise ValueError("WTF-PAD tuning percentile must be in (0, 0.5]")
    z = float(stats.norm.ppf(percentile))
    multiplier = math.exp(z * z / 2.0)
    if candidate.name == "normal":
        location, scale = candidate.parameters
        return (_float(location + scale * z), _float(scale * multiplier))
    shape, location, scale = candidate.parameters
    if candidate.name != "lognormal" or location != 0.0:
        raise ValueError("WTF-PAD lognormal fit has invalid parameters")
    return (
        _float(shape * multiplier),
        0.0,
        _float(scale * math.exp(shape * z)),
    )


def _exponential_edges(maximum_us: int) -> tuple[int, ...]:
    maximum = int(maximum_us)
    if not FINITE_BINS <= maximum <= MAX_U64:
        raise ValueError("WTF-PAD fitted percentile cannot represent 19 finite microsecond bins")
    denominator = (1 << FINITE_BINS) - 1
    edges: list[int] = []
    for index in range(FINITE_BINS):
        exponential = math.ceil(maximum * ((1 << (index + 1)) - 1) / denominator)
        lower = edges[-1] + 1 if edges else 1
        upper = maximum - (FINITE_BINS - index - 1)
        edges.append(min(max(exponential, lower), upper))
    result = tuple(edges)
    if any(left >= right for left, right in zip(result, result[1:])) or result[-1] != maximum:
        raise ValueError("WTF-PAD exponential edges are not representable")
    return result


def _apportion_tokens(probabilities: np.ndarray, total: int) -> tuple[int, ...]:
    values = np.asarray(probabilities, dtype=float)
    if values.ndim != 1 or len(values) != FINITE_BINS:
        raise ValueError("WTF-PAD probabilities have the wrong bin count")
    if np.any(~np.isfinite(values)) or np.any(values < 0) or float(values.sum()) <= 0:
        raise ValueError("WTF-PAD probabilities are invalid")
    scaled = values / float(values.sum()) * total
    tokens = np.floor(scaled).astype(np.int64)
    remainder = total - int(tokens.sum())
    order = sorted(range(len(tokens)), key=lambda index: (-(scaled[index] - tokens[index]), index))
    for index in order[:remainder]:
        tokens[index] += 1
    return tuple(int(value) for value in tokens)


def _rounded_positive_tokens(value: float, label: str) -> int:
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"WTF-PAD {label} infinity-token formula is invalid")
    rounded = int(math.ceil(value))
    if rounded > MAX_U32:
        raise ValueError(f"WTF-PAD {label} infinity-token count exceeds u32")
    return rounded


def _float(value: float) -> float:
    result = float(round(float(value), 15))
    if not math.isfinite(result):
        raise ValueError("WTF-PAD fit produced a non-finite value")
    return 0.0 if result == -0.0 else result
