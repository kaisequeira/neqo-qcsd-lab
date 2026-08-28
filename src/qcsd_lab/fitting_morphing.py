"""Deterministic padding-only Traffic Morphing parameter fitting."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np

from .fitting_trace import FittingTrace


GENERATED_BY = "qcsd_lab.fitting_morphing 2.0.0"
DEFAULT_BUCKETS = (64, 150, 300, 500, 700, 900, 1_100, 1_200)
HIGHS_OPTIONS = {
    "presolve": True,
    "primal_feasibility_tolerance": 1e-9,
    "dual_feasibility_tolerance": 1e-9,
    "ipm_optimality_tolerance": 1e-10,
}


@dataclass(frozen=True)
class MorphResult:
    buckets: tuple[int, ...]
    rows: tuple[tuple[float, ...], ...]
    source_distribution: tuple[float, ...]
    target_distribution: tuple[float, ...]
    realized_distribution: tuple[float, ...]
    l1_distance: float
    expected_added_bytes: float


@dataclass(frozen=True)
class DirectedFit:
    source: str
    target: str
    outgoing: MorphResult
    incoming: MorphResult
    source_outgoing_packets: int
    source_incoming_packets: int

    @property
    def fidelity_cost(self) -> float:
        return self.outgoing.l1_distance + self.incoming.l1_distance

    @property
    def byte_cost(self) -> float:
        return (
            self.source_outgoing_packets * self.outgoing.expected_added_bytes
            + self.source_incoming_packets * self.incoming.expected_added_bytes
        )


def fit_traffic_morphing(
    traces: Mapping[str, Sequence[FittingTrace]],
    *,
    buckets: Sequence[int] = DEFAULT_BUCKETS,
) -> tuple[dict[str, object], dict[str, object]]:
    """Fit every directed edge, then select one minimum-cost derangement."""

    names = tuple(traces)
    if len(names) < 2:
        raise ValueError("Traffic Morphing fitting requires at least two workloads")
    if any(not traces[name] for name in names):
        raise ValueError("Traffic Morphing workloads require at least one training trace")
    edges = _validated_buckets(buckets)
    distributions: dict[tuple[str, str], tuple[np.ndarray, int]] = {}
    corpus_bucket_counts: list[dict[str, object]] = []
    for name in names:
        workload_counts: dict[str, object] = {"workload_id": name}
        for direction in ("outgoing", "incoming"):
            distribution, total, counts = _size_distribution_with_counts(
                traces[name], direction, edges
            )
            distributions[(name, direction)] = (distribution, total)
            workload_counts[direction] = [int(value) for value in counts]
        corpus_bucket_counts.append(workload_counts)

    candidates: dict[tuple[str, str], DirectedFit] = {}
    for source in names:
        for target in names:
            if source == target:
                continue
            source_out, count_out = distributions[(source, "outgoing")]
            target_out, _ = distributions[(target, "outgoing")]
            source_in, count_in = distributions[(source, "incoming")]
            target_in, _ = distributions[(target, "incoming")]
            candidates[(source, target)] = DirectedFit(
                source=source,
                target=target,
                outgoing=morphing_matrix(source_out, target_out, edges),
                incoming=morphing_matrix(source_in, target_in, edges),
                source_outgoing_packets=count_out,
                source_incoming_packets=count_in,
            )

    selection = minimum_cost_derangement(names, candidates)
    profiles = [_profile_json(candidates[(source, target)]) for source, target in selection]
    artifact: dict[str, object] = {
        "adaptation": "qcsd-client-only",
        "buckets": list(edges),
        "generated_by": GENERATED_BY,
        "paper_equivalent": False,
        "profiles": profiles,
        "schema_version": 2,
        "udp_payload_ceiling": edges[-1],
    }
    diagnostics: dict[str, object] = {
        "algorithm": "all-directed-padding-only-lp-then-minimum-cost-derangement",
        "corpus_bucket_counts": corpus_bucket_counts,
        "candidate_costs": [
            {
                "source": source,
                "target": target,
                "l1_cost": candidates[(source, target)].fidelity_cost,
                "estimated_added_bytes": candidates[(source, target)].byte_cost,
            }
            for source in names
            for target in names
            if source != target
        ],
        "selected_mapping": [
            {
                "source": source,
                "target": target,
                "l1_cost": candidates[(source, target)].fidelity_cost,
                "estimated_added_bytes": candidates[(source, target)].byte_cost,
            }
            for source, target in selection
        ],
    }
    return artifact, diagnostics


def size_distribution(
    traces: Sequence[FittingTrace], direction: str, buckets: Sequence[int]
) -> tuple[np.ndarray, int]:
    distribution, total, _counts = _size_distribution_with_counts(traces, direction, buckets)
    return distribution, total


def _size_distribution_with_counts(
    traces: Sequence[FittingTrace], direction: str, buckets: Sequence[int]
) -> tuple[np.ndarray, int, np.ndarray]:
    if direction not in {"outgoing", "incoming"}:
        raise ValueError("direction must be outgoing or incoming")
    edges = _validated_buckets(buckets)
    counts = np.zeros(len(edges), dtype=np.int64)
    for trace in traces:
        for packet in trace.packets:
            if packet.direction != direction:
                continue
            index = min(
                int(np.searchsorted(edges, packet.length_bytes, side="left")), len(edges) - 1
            )
            counts[index] += 1
    total = int(counts.sum())
    if total == 0:
        raise ValueError(f"fitting traces contain no {direction} packets")
    return counts.astype(float) / total, total, counts


def morphing_matrix(source: np.ndarray, target: np.ndarray, buckets: Sequence[int]) -> MorphResult:
    """Solve L1, bytes, then the lexicographically minimum row-major flow with HiGHS."""

    from scipy.optimize import linprog

    edges = _validated_buckets(buckets)
    source_distribution = _validated_distribution(source, len(edges), "source")
    target_distribution = _validated_distribution(target, len(edges), "target")
    count = len(edges)
    matrix_variables = count * count
    variables = matrix_variables + count

    equalities: list[np.ndarray] = []
    equality_values: list[float] = []
    for row in range(count):
        constraint = np.zeros(variables, dtype=float)
        constraint[row * count : (row + 1) * count] = 1.0
        equalities.append(constraint)
        equality_values.append(1.0)

    inequalities: list[np.ndarray] = []
    upper_values: list[float] = []
    for column in range(count):
        positive = np.zeros(variables, dtype=float)
        negative = np.zeros(variables, dtype=float)
        for row in range(count):
            coefficient = source_distribution[row]
            positive[row * count + column] = coefficient
            negative[row * count + column] = -coefficient
        positive[matrix_variables + column] = -1.0
        negative[matrix_variables + column] = -1.0
        inequalities.extend((positive, negative))
        upper_values.extend(
            (float(target_distribution[column]), -float(target_distribution[column]))
        )

    bounds: list[tuple[float, float | None]] = []
    for row in range(count):
        for column in range(count):
            if source_distribution[row] == 0:
                bounds.append((1.0, 1.0) if row == column else (0.0, 0.0))
            elif column < row:
                bounds.append((0.0, 0.0))
            else:
                bounds.append((0.0, None))
    bounds.extend((0.0, None) for _ in range(count))

    distance_objective = np.zeros(variables, dtype=float)
    distance_objective[matrix_variables:] = 1.0
    first = linprog(
        distance_objective,
        A_eq=np.asarray(equalities),
        b_eq=np.asarray(equality_values),
        A_ub=np.asarray(inequalities),
        b_ub=np.asarray(upper_values),
        bounds=bounds,
        method="highs",
        options=HIGHS_OPTIONS,
    )
    if not first.success or first.x is None:
        raise ValueError(f"Traffic Morphing fidelity LP failed: {first.message}")

    distance_bound = np.zeros(variables, dtype=float)
    distance_bound[matrix_variables:] = 1.0
    overhead_objective = np.zeros(variables, dtype=float)
    for row in range(count):
        for column in range(count):
            overhead_objective[row * count + column] = source_distribution[row] * (
                edges[column] - edges[row]
            )
    second = linprog(
        overhead_objective,
        A_eq=np.asarray([*equalities, distance_bound]),
        b_eq=np.asarray([*equality_values, float(first.fun)]),
        A_ub=np.asarray(inequalities),
        b_ub=np.asarray(upper_values),
        bounds=bounds,
        method="highs",
        options=HIGHS_OPTIONS,
    )
    if not second.success or second.x is None:
        raise ValueError(f"Traffic Morphing overhead LP failed: {second.message}")

    # The first two objectives can leave a face of equivalent conditional
    # flows. Minimize each row-major matrix cell in turn, fixing every prior
    # optimum before advancing. This is an explicit, stable canonical choice;
    # it is not whatever basic feasible solution a particular HiGHS release
    # happens to return.
    canonical_bounds = list(bounds)
    canonical_equalities = [*equalities, distance_bound, overhead_objective]
    canonical_equality_values = [
        *equality_values,
        float(first.fun),
        float(second.fun),
    ]
    canonical = second
    for variable in range(matrix_variables):
        lower, upper = canonical_bounds[variable]
        if upper is not None and lower == upper:
            continue
        objective = np.zeros(variables, dtype=float)
        objective[variable] = 1.0
        solution = linprog(
            objective,
            A_eq=np.asarray(canonical_equalities),
            b_eq=np.asarray(canonical_equality_values),
            A_ub=np.asarray(inequalities),
            b_ub=np.asarray(upper_values),
            bounds=canonical_bounds,
            method="highs",
            options=HIGHS_OPTIONS,
        )
        if not solution.success or solution.x is None:
            raise ValueError(
                f"Traffic Morphing row-major canonicalization failed at cell {variable}: "
                f"{solution.message}"
            )
        value = float(solution.x[variable])
        if abs(value) < 1e-10:
            value = 0.0
        elif upper is not None and abs(value - upper) < 1e-10:
            value = upper
        fixed_cell = np.zeros(variables, dtype=float)
        fixed_cell[variable] = 1.0
        canonical_equalities.append(fixed_cell)
        canonical_equality_values.append(value)
        canonical = solution

    matrix = np.asarray(canonical.x[:matrix_variables], dtype=float).reshape((count, count))
    matrix[np.abs(matrix) <= 1e-8] = 0.0
    if np.any(matrix < 0):
        raise ValueError("Traffic Morphing solver produced a negative probability")
    for row in range(count):
        row_total = float(matrix[row].sum())
        if row_total <= 0:
            raise ValueError(f"Traffic Morphing solver produced empty row {row}")
        matrix[row] /= row_total
        if np.any(matrix[row, :row] > 1e-10):
            raise ValueError(f"Traffic Morphing solver produced downward mass in row {row}")

    realized = matrix.T @ source_distribution
    l1 = float(np.abs(realized - target_distribution).sum())
    if l1 < 1e-9:
        l1 = 0.0
    if l1 > float(first.fun) + 1e-7:
        raise ValueError("Traffic Morphing second stage changed the optimal L1 distance")
    added = float(
        sum(
            source_distribution[row] * matrix[row, column] * (edges[column] - edges[row])
            for row in range(count)
            for column in range(row, count)
        )
    )
    if abs(added) < 1e-7:
        added = 0.0
    if abs(added - float(second.fun)) > 1e-7:
        raise ValueError("Traffic Morphing canonicalization changed the byte optimum")
    serialized_rows = tuple(tuple(_canonical_float(value) for value in row) for row in matrix)
    serialized_source = tuple(_canonical_float(value) for value in source_distribution)
    serialized_target = tuple(_canonical_float(value) for value in target_distribution)
    serialized_realized = tuple(
        _canonical_float(
            math.fsum(serialized_source[row] * serialized_rows[row][column] for row in range(count))
        )
        for column in range(count)
    )
    serialized_l1 = _canonical_float(
        math.fsum(
            abs(actual - target)
            for actual, target in zip(serialized_realized, serialized_target, strict=True)
        )
    )
    serialized_added = _canonical_float(
        math.fsum(
            serialized_source[row] * serialized_rows[row][column] * (edges[column] - edges[row])
            for row in range(count)
            for column in range(row, count)
        )
    )
    return MorphResult(
        buckets=edges,
        rows=serialized_rows,
        source_distribution=serialized_source,
        target_distribution=serialized_target,
        realized_distribution=serialized_realized,
        l1_distance=serialized_l1,
        expected_added_bytes=serialized_added,
    )


def minimum_cost_derangement(
    names: Sequence[str], candidates: Mapping[tuple[str, str], DirectedFit]
) -> tuple[tuple[str, str], ...]:
    """Return the exact lexicographic minimum no-self assignment.

    The former implementation enumerated every permutation, which made the
    fitter unusable beyond very small cohorts.  This implementation folds the
    three objective stages into arbitrary-precision integer edge weights and
    solves the resulting assignment with the Hungarian algorithm.  Converting
    each finite IEEE-754 input to a common power-of-two denominator preserves
    even sub-ULP-looking differences such as the historical ``4e-16``
    regression fixture; no tolerance or rounded weighted sum participates in
    selecting the mapping.
    """

    ordered = tuple(names)
    if len(ordered) < 2 or len(set(ordered)) != len(ordered):
        raise ValueError("Traffic Morphing has no feasible no-self target assignment")

    edge_keys = tuple(
        (source, target)
        for source in ordered
        for target in ordered
        if source != target
    )
    try:
        edges = tuple(candidates[key] for key in edge_keys)
    except KeyError as error:
        raise ValueError(
            "Traffic Morphing has no feasible no-self target assignment"
        ) from error

    fidelity = _common_binary_integers(edge.fidelity_cost for edge in edges)
    byte_cost = _common_binary_integers(edge.byte_cost for edge in edges)
    fidelity_by_edge = dict(zip(edge_keys, fidelity, strict=True))
    bytes_by_edge = dict(zip(edge_keys, byte_cost, strict=True))

    # Every assignment selects exactly len(ordered) edges.  Subtracting each
    # stage's global minimum is therefore a constant shift.  The stage scales
    # are strict upper bounds on every lower-priority aggregate, making this a
    # lossless scalar representation of:
    #   (sum fidelity, sum bytes, tuple(targets)).
    minimum_fidelity = min(fidelity)
    minimum_bytes = min(byte_cost)
    byte_span = max(byte_cost) - minimum_bytes
    byte_stage_scale = len(ordered) * byte_span + 1
    lexical_base = len(ordered) + 1
    lexical_stage_scale = lexical_base ** len(ordered)
    lexical_rank = {name: rank for rank, name in enumerate(sorted(ordered))}
    lexical_places = tuple(
        lexical_base ** (len(ordered) - source_index - 1)
        for source_index in range(len(ordered))
    )

    weights: list[list[int | None]] = []
    for source_index, source in enumerate(ordered):
        row: list[int | None] = []
        for target in ordered:
            if source == target:
                row.append(None)
                continue
            primary = fidelity_by_edge[(source, target)] - minimum_fidelity
            secondary = bytes_by_edge[(source, target)] - minimum_bytes
            lexical = lexical_rank[target] * lexical_places[source_index]
            row.append(
                (primary * byte_stage_scale + secondary) * lexical_stage_scale
                + lexical
            )
        weights.append(row)

    assignment = _minimum_weight_assignment(weights)
    return tuple(
        (source, ordered[target_index])
        for source, target_index in zip(ordered, assignment, strict=True)
    )


def _common_binary_integers(values: Iterable[float]) -> tuple[int, ...]:
    """Represent finite floats over one exact power-of-two denominator."""

    checked = tuple(_cost_key(value) for value in values)
    ratios = tuple(value.as_integer_ratio() for value in checked)
    exponents: list[int] = []
    for _numerator, denominator in ratios:
        exponent = denominator.bit_length() - 1
        if denominator != 1 << exponent:
            raise AssertionError("an IEEE-754 denominator was not a power of two")
        exponents.append(exponent)
    common_exponent = max(exponents, default=0)
    return tuple(
        numerator << (common_exponent - exponent)
        for (numerator, _denominator), exponent in zip(ratios, exponents, strict=True)
    )


def _minimum_weight_assignment(weights: Sequence[Sequence[int | None]]) -> tuple[int, ...]:
    """Solve a square sparse integer assignment in O(n^3), deterministically."""

    size = len(weights)
    if not size or any(len(row) != size for row in weights):
        raise ValueError("Traffic Morphing assignment matrix must be non-empty and square")

    # One-indexed shortest augmenting path form of the Hungarian algorithm.
    # Python integers retain the exact composite objective regardless of cohort
    # size, unlike a floating weighted objective passed to an LP/MILP solver.
    row_potential = [0] * (size + 1)
    column_potential = [0] * (size + 1)
    matched_row = [0] * (size + 1)
    predecessor = [0] * (size + 1)

    for source in range(1, size + 1):
        matched_row[0] = source
        minimum_slack: list[int | None] = [None] * (size + 1)
        used = [False] * (size + 1)
        column = 0
        while True:
            used[column] = True
            active_row = matched_row[column]
            delta: int | None = None
            next_column = 0
            for candidate_column in range(1, size + 1):
                if used[candidate_column]:
                    continue
                weight = weights[active_row - 1][candidate_column - 1]
                if weight is not None:
                    slack = (
                        weight
                        - row_potential[active_row]
                        - column_potential[candidate_column]
                    )
                    if (
                        minimum_slack[candidate_column] is None
                        or slack < minimum_slack[candidate_column]
                    ):
                        minimum_slack[candidate_column] = slack
                        predecessor[candidate_column] = column
                candidate_slack = minimum_slack[candidate_column]
                if candidate_slack is not None and (
                    delta is None
                    or candidate_slack < delta
                    or (candidate_slack == delta and candidate_column < next_column)
                ):
                    delta = candidate_slack
                    next_column = candidate_column
            if delta is None:
                raise ValueError("Traffic Morphing has no feasible no-self target assignment")
            for candidate_column in range(size + 1):
                if used[candidate_column]:
                    row_potential[matched_row[candidate_column]] += delta
                    column_potential[candidate_column] -= delta
                elif minimum_slack[candidate_column] is not None:
                    minimum_slack[candidate_column] -= delta
            column = next_column
            if matched_row[column] == 0:
                break

        while column:
            prior = predecessor[column]
            matched_row[column] = matched_row[prior]
            column = prior

    assignment = [-1] * size
    for column in range(1, size + 1):
        source = matched_row[column]
        if source:
            assignment[source - 1] = column - 1
    if any(target < 0 for target in assignment):
        raise ValueError("Traffic Morphing has no feasible no-self target assignment")
    return tuple(assignment)


def _profile_json(edge: DirectedFit) -> dict[str, object]:
    return {
        "incoming": _direction_json(edge.incoming),
        "outgoing": _direction_json(edge.outgoing),
        "source": edge.source,
        "target": edge.target,
    }


def _direction_json(result: MorphResult) -> dict[str, object]:
    return {
        "expected_added_bytes": result.expected_added_bytes,
        "l1_distance": result.l1_distance,
        "realized_distribution": list(result.realized_distribution),
        "rows": [list(row) for row in result.rows],
        "source_distribution": list(result.source_distribution),
        "target_distribution": list(result.target_distribution),
    }


def _validated_buckets(buckets: Sequence[int]) -> tuple[int, ...]:
    values = tuple(buckets)
    if not values or any(type(item) is not int for item in values):
        raise ValueError("Traffic Morphing buckets must be non-empty integers")
    if values[0] < 1 or values[-1] != 1_200:
        raise ValueError("Traffic Morphing research buckets must terminate at 1200 bytes")
    if any(left >= right for left, right in zip(values, values[1:])):
        raise ValueError("Traffic Morphing buckets must be strictly increasing")
    return values


def _validated_distribution(values: np.ndarray, width: int, label: str) -> np.ndarray:
    result = np.asarray(values, dtype=float)
    if result.ndim != 1 or len(result) != width:
        raise ValueError(f"Traffic Morphing {label} distribution has the wrong width")
    if not np.all(np.isfinite(result)) or np.any(result < 0) or float(result.sum()) <= 0:
        raise ValueError(f"Traffic Morphing {label} distribution is invalid")
    return result / float(result.sum())


def _canonical_float(value: float) -> float:
    result = float(round(float(value), 15))
    return 0.0 if result == -0.0 else result


def _cost_key(value: float) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Traffic Morphing assignment cost must be finite")
    return result
