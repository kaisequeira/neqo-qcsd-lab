"""Deterministic typed-event fitting for Walkie-Talkie burst moulds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .fitting_trace import FittingTrace


GENERATED_BY = "qcsd_lab.fitting_walkie_talkie 2.2.0"
PACKET_SIZE = 1_200
PARSER_ALLOWANCE_CEILING_BYTES = 1_000
RECEIVER_CONTINUATION_CELLS = 1
MAX_U32 = 2**32 - 1
MAX_U64 = 2**64 - 1
BURST_DEFINITION = "global-application-batch-direction-transitions"
CELL_BYTE_DOMAIN = "http3-request-stream-offset.bytes"


@dataclass(frozen=True)
class BurstPair:
    outgoing: int
    incoming: int
    batch_end: bool = True


@dataclass(frozen=True)
class ProfileEnvelope:
    bursts: tuple[BurstPair, ...]
    visit_count: int
    varying_components: int
    maximum_component_spread: int


def fit_walkie_talkie(
    traces: Mapping[str, Sequence[FittingTrace]],
) -> tuple[dict[str, object], dict[str, object]]:
    """Envelope visits per workload, then solve a full-cohort perfect matching."""

    names = tuple(traces)
    if not names or len(names) % 2:
        raise ValueError("Walkie-Talkie fitting requires a positive even workload count")
    envelopes: dict[str, ProfileEnvelope] = {}
    training_inputs: dict[str, tuple[str, ...]] = {}
    training_visits: list[dict[str, object]] = []
    for name in names:
        visits = tuple(sorted(traces[name], key=lambda trace: (trace.visit, trace.sample_id)))
        if not visits:
            raise ValueError(f"Walkie-Talkie workload {name!r} has no fitting visits")
        if len({trace.visit for trace in visits}) != len(visits):
            raise ValueError(f"Walkie-Talkie workload {name!r} has duplicate visits")
        sequences = tuple(burst_sequence(trace) for trace in visits)
        envelopes[name] = componentwise_envelope(sequences)
        inputs = tuple(trace.training_input_sha256 for trace in visits)
        if len(inputs) != len(set(inputs)):
            raise ValueError(f"Walkie-Talkie workload {name!r} repeats a training input")
        training_inputs[name] = inputs
        training_visits.append(
            {
                "workload_id": name,
                "visits": [
                    {
                        "visit": trace.visit,
                        "training_input_sha256": trace.training_input_sha256,
                        "bursts": _bursts_json(sequence),
                        "batch_ends": _batch_ends(sequence),
                    }
                    for trace, sequence in zip(visits, sequences, strict=True)
                ],
            }
        )

    pairs = minimum_weight_perfect_matching(envelopes)
    lexical_names = tuple(sorted(names))
    candidate_costs = [
        {
            "left": left,
            "right": right,
            "base_matching_cost_packets": symmetric_mold_padding_cost(
                envelopes[left].bursts, envelopes[right].bursts
            ),
            "matching_cost_packets": mold_padding_cost(
                envelopes[left].bursts, envelopes[right].bursts
            ),
        }
        for index, left in enumerate(lexical_names)
        for right in lexical_names[index + 1 :]
    ]
    profiles: list[dict[str, object]] = []
    pair_receipt: list[dict[str, object]] = []
    for real, decoy, base_cost in pairs:
        real_envelope = envelopes[real]
        decoy_envelope = envelopes[decoy]
        molded = tuple(mold(real_envelope.bursts, decoy_envelope.bursts))
        expected_base_cost = symmetric_mold_padding_cost(
            real_envelope.bursts, decoy_envelope.bursts
        )
        if base_cost != expected_base_cost:
            raise AssertionError("Walkie-Talkie matching cost changed during encoding")
        matching_cost = mold_padding_cost(real_envelope.bursts, decoy_envelope.bursts)
        total_bytes = _total_packets(molded) * PACKET_SIZE
        if total_bytes > MAX_U64:
            raise ValueError("Walkie-Talkie total scheduled bytes exceed u64")
        profiles.append(
            {
                "real": real,
                "decoy": decoy,
                "matching_cost_packets": matching_cost,
                "training_inputs": {
                    "real": list(training_inputs[real]),
                    "decoy": list(training_inputs[decoy]),
                },
                "variation": {
                    "real": _variation_json(real_envelope),
                    "decoy": _variation_json(decoy_envelope),
                },
                "source_envelopes": {
                    "real": _bursts_json(real_envelope.bursts),
                    "decoy": _bursts_json(decoy_envelope.bursts),
                },
                "batch_ends": {
                    "real": _batch_ends(real_envelope.bursts),
                    "decoy": _batch_ends(decoy_envelope.bursts),
                },
                "molded_batch_ends": _batch_ends(molded),
                "total_scheduled_bytes": total_bytes,
                "bursts": _bursts_json(molded),
            }
        )
        pair_receipt.append(
            {
                "real": real,
                "decoy": decoy,
                "base_matching_cost_packets": base_cost,
                "matching_cost_packets": matching_cost,
            }
        )

    artifact: dict[str, object] = {
        "adaptation": "qcsd-client-only",
        "burst_definition": BURST_DEFINITION,
        "cell_byte_domain": CELL_BYTE_DOMAIN,
        "schema_version": 6,
        "generated_by": GENERATED_BY,
        "matching_algorithm": "minimum-base-symmetric-mold-padding-cost-one-to-one",
        "paper_equivalent": False,
        "packet_size": PACKET_SIZE,
        "receiver_continuation": receiver_continuation_contract(),
        "profiles": profiles,
    }
    diagnostics: dict[str, object] = {
        "algorithm": "full-cohort-minimum-weight-perfect-matching",
        "pairing_objective": "minimum-base-symmetric-mold-padding-cost",
        "receiver_continuation": receiver_continuation_contract(),
        "candidate_pair_costs": candidate_costs,
        "selected_pairs": pair_receipt,
        "training_visits": training_visits,
    }
    return artifact, diagnostics


def burst_sequence(trace: FittingTrace, *, packet_size: int = PACKET_SIZE) -> tuple[BurstPair, ...]:
    """Extract fixed cells from explicit global batch and STREAM observations."""

    if not 64 <= packet_size <= 65_535:
        raise ValueError("Walkie-Talkie packet size must lie within [64, 65535]")
    if not trace.observations:
        raise ValueError(f"Walkie-Talkie trace has no typed observations: {trace.sample_id}")
    stream_roles: dict[tuple[int, int], str] = {}
    active_ranges: dict[tuple[int, int], list[tuple[int, int]]] | None = None
    active_segments: list[tuple[str, int]] | None = None
    pairs: list[BurstPair] = []
    completed = False
    completion_count = 0
    for observation in trace.observations:
        details = observation.details
        kind = observation.kind
        if kind == "stream_opened":
            key = _stream_key(details, trace.sample_id)
            role = _role(details.get("role"), trace.sample_id)
            if key in stream_roles:
                raise ValueError(
                    f"Walkie-Talkie stream-open evidence is duplicated: {trace.sample_id}"
                )
            stream_roles[key] = role
            continue
        if kind == "application_batch_started":
            if completed:
                raise ValueError(
                    f"Walkie-Talkie batch starts after application completion: {trace.sample_id}"
                )
            if active_ranges is not None:
                raise ValueError(f"Walkie-Talkie application batches overlap: {trace.sample_id}")
            active_ranges = {}
            active_segments = []
            continue
        if kind == "application_batch_completed":
            if active_ranges is None or active_segments is None:
                raise ValueError(f"Walkie-Talkie batch completion has no start: {trace.sample_id}")
            pairs.extend(
                _batch_pairs(
                    active_segments,
                    packet_size,
                    batch_index=sum(pair.batch_end for pair in pairs),
                    label=trace.sample_id,
                )
            )
            active_ranges = None
            active_segments = None
            continue
        if kind == "application_complete":
            completion_count += 1
            if active_ranges is not None or completion_count != 1:
                raise ValueError(
                    f"Walkie-Talkie application completion is unbalanced: {trace.sample_id}"
                )
            completed = True
            continue
        if kind == "stream_data_transmitted":
            if _role(details.get("role"), trace.sample_id) != "application":
                continue
            if active_ranges is None or active_segments is None:
                raise ValueError(
                    f"Walkie-Talkie outgoing STREAM data lies outside a batch: {trace.sample_id}"
                )
            key = _stream_key(details, trace.sample_id)
            if stream_roles.get(key) not in {None, "application"}:
                raise ValueError(
                    f"Walkie-Talkie transmitted role contradicts stream-open: {trace.sample_id}"
                )
            offset = _uint(details.get("offset"), "offset", trace.sample_id)
            count = _positive_uint(details.get("bytes"), "bytes", trace.sample_id)
            end = offset + count
            if end > MAX_U64:
                raise ValueError(f"Walkie-Talkie STREAM range exceeds u64: {trace.sample_id}")
            ranges = active_ranges.setdefault(key, [])
            before = _unique_range_bytes(ranges)
            ranges.append((offset, end))
            unique = _unique_range_bytes(ranges) - before
            if unique:
                _append_segment(active_segments, "outgoing", unique, trace.sample_id)
            continue
        if kind == "bytes_read":
            key = _stream_key(details, trace.sample_id)
            role = stream_roles.get(key)
            if role is None:
                raise ValueError(
                    f"Walkie-Talkie receive has no stream-open evidence: {trace.sample_id}"
                )
            if role != "application":
                continue
            count = _uint(details.get("bytes"), "bytes", trace.sample_id)
            if count == 0:
                continue
            if active_ranges is None or active_segments is None:
                raise ValueError(
                    f"Walkie-Talkie incoming STREAM data lies outside a batch: {trace.sample_id}"
                )
            _append_segment(
                active_segments,
                "incoming",
                count,
                trace.sample_id,
            )
    if active_ranges is not None:
        raise ValueError(f"Walkie-Talkie batch has no completion marker: {trace.sample_id}")
    if completion_count != 1 or not completed:
        raise ValueError(
            f"Walkie-Talkie trace requires one application_complete: {trace.sample_id}"
        )
    if not pairs:
        raise ValueError(f"Walkie-Talkie trace contains no application batch: {trace.sample_id}")
    return tuple(pairs)


def componentwise_envelope(visits: Sequence[Sequence[BurstPair]]) -> ProfileEnvelope:
    if not visits or any(not visit for visit in visits):
        raise ValueError("Walkie-Talkie envelopes require non-empty visits")
    checked = [tuple(_validated_pair(pair, "training burst") for pair in visit) for visit in visits]
    batches = [_split_batches(visit, "training visit") for visit in checked]
    if len({len(value) for value in batches}) != 1:
        raise ValueError("Walkie-Talkie visits must have the same application-batch count")
    reference_structure = tuple(
        tuple((pair.outgoing > 0, pair.incoming > 0) for pair in batch) for batch in batches[0]
    )
    if any(
        tuple(tuple((pair.outgoing > 0, pair.incoming > 0) for pair in batch) for batch in visit)
        != reference_structure
        for visit in batches[1:]
    ):
        raise ValueError("Walkie-Talkie visits must have the same per-batch direction structure")
    envelope: list[BurstPair] = []
    varying = 0
    maximum_spread = 0
    for batch_index in range(len(batches[0])):
        cohort = [visit[batch_index] for visit in batches]
        width = len(cohort[0])
        for index in range(width):
            outgoing = [batch[index].outgoing for batch in cohort]
            incoming = [batch[index].incoming for batch in cohort]
            for values in (outgoing, incoming):
                spread = max(values) - min(values)
                if spread:
                    varying += 1
                    maximum_spread = max(maximum_spread, spread)
            envelope.append(BurstPair(max(outgoing), max(incoming), index == width - 1))
    return ProfileEnvelope(tuple(envelope), len(checked), varying, maximum_spread)


def symmetric_mold(real: Sequence[BurstPair], decoy: Sequence[BurstPair]) -> list[BurstPair]:
    """Return the batch-aware element-wise maximum of two observed envelopes."""

    real_batches = _split_batches(real, "real mould source")
    decoy_batches = _split_batches(decoy, "decoy mould source")
    if not real_batches or not decoy_batches:
        raise ValueError("Walkie-Talkie mould sources must not be empty")
    result: list[BurstPair] = []
    for batch_index in range(max(len(real_batches), len(decoy_batches))):
        real_batch = real_batches[batch_index] if batch_index < len(real_batches) else ()
        decoy_batch = decoy_batches[batch_index] if batch_index < len(decoy_batches) else ()
        width = max(len(real_batch), len(decoy_batch))
        for index in range(width):
            left = real_batch[index] if index < len(real_batch) else BurstPair(0, 0)
            right = decoy_batch[index] if index < len(decoy_batch) else BurstPair(0, 0)
            result.append(
                BurstPair(
                    max(left.outgoing, right.outgoing),
                    max(left.incoming, right.incoming),
                    index == width - 1,
                )
            )
    return result


def mold(real: Sequence[BurstPair], decoy: Sequence[BurstPair]) -> list[BurstPair]:
    """Return the runtime mould with one bounded receiver-continuation cell."""

    result: list[BurstPair] = []
    for pair in symmetric_mold(real, decoy):
        incoming = pair.incoming
        if incoming:
            if incoming > MAX_U32 - RECEIVER_CONTINUATION_CELLS:
                raise ValueError("Walkie-Talkie adapted incoming component exceeds u32")
            incoming += RECEIVER_CONTINUATION_CELLS
        result.append(BurstPair(pair.outgoing, incoming, pair.batch_end))
    return result


def mold_padding_cost(real: Sequence[BurstPair], decoy: Sequence[BurstPair]) -> int:
    molded = mold(real, decoy)
    return _padding_cost(molded, real, decoy, "runtime")


def symmetric_mold_padding_cost(real: Sequence[BurstPair], decoy: Sequence[BurstPair]) -> int:
    molded = symmetric_mold(real, decoy)
    return _padding_cost(molded, real, decoy, "base")


def _padding_cost(
    molded: Sequence[BurstPair],
    real: Sequence[BurstPair],
    decoy: Sequence[BurstPair],
    label: str,
) -> int:
    molded_packets = _total_packets(molded)
    source_packets = _total_packets(real) + _total_packets(decoy)
    doubled = molded_packets * 2
    if doubled > MAX_U64 or source_packets > MAX_U64 or doubled < source_packets:
        raise ValueError(f"Walkie-Talkie {label} matching cost exceeds u64")
    return doubled - source_packets


def receiver_continuation_contract() -> dict[str, object]:
    """Return the exact, JSON-safe post-mould receiver-continuation contract."""

    raw_headroom = RECEIVER_CONTINUATION_CELLS * PACKET_SIZE
    if raw_headroom <= PARSER_ALLOWANCE_CEILING_BYTES:
        raise AssertionError("Walkie-Talkie continuation must exceed the parser allowance")
    return {
        **schema_five_receiver_continuation_contract(),
        "qualified_chaff_manifest_policy": (
            "distinct-schema-one-qualified-navigation-root-only;exact-lowercase-accept-accept-"
            "encoding-accept-language-projection;application-request-headers-unchanged"
        ),
        "qualified_chaff_response_policy": (
            "three-independent-five-way-concurrent-unshaped-production-nonblocking-qpack-"
            "qualifications-derive-compact-status-normalized-content-encoding-body-bytes-body-"
            "sha256;runtime-complete-responses-must-match-derived-identity;runtime-partial-"
            "responses-have-null-identity-match-fields"
        ),
        "first_cell_prefix_pack_precondition": (
            "three-independent-production-nonblocking-qpack-runs-after-peer-settings-and-"
            "drained-h3-control-qpack-warmup-open-one-full-application-root-plus-five-qualified-"
            "compact-chaff-requests-before-exactly-one-1200-byte-molded-packet-target;all-post-"
            "cutoff-stream-transmissions-owned-by-sole-target;application-and-maximum-receiver-"
            "continuation-reserve-horizon+1-chaff-request-streams-contiguous-through-fin;required-"
            "chaff-peer-acknowledged-through-fin;no-pending-application-required-chaff-or-h3-qpack-"
            "stream-output;zero-targetless-stream-bytes"
        ),
        "qualification_binding_policy": (
            "raw-sha256-per-workload-binds-chaff-qualification-sidecar-prefix-pack-spec-and-"
            "final-qualified-chaff-manifest;runtime-requires-exact-final-manifest-and-embedded-"
            "prefix-spec-hashes"
        ),
    }


def schema_five_receiver_continuation_contract() -> dict[str, object]:
    """Return the frozen historical schema-five receiver metadata oracle."""

    raw_headroom = RECEIVER_CONTINUATION_CELLS * PACKET_SIZE
    if raw_headroom <= PARSER_ALLOWANCE_CEILING_BYTES:
        raise AssertionError("Walkie-Talkie continuation must exceed the parser allowance")
    return {
        "allocation_policy": (
            "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell"
        ),
        "application_order": "after-symmetric-elementwise-mold",
        "batch_end_release_policy": (
            "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate"
        ),
        "base_allocation_policy": (
            "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;"
            "exact-capacity-before-bounded-framing-claims"
        ),
        "causal_capacity_precondition": (
            "first-molded-component-outgoing>0;max_chaff_streams>=maximum-receiver-continuation-"
            "reserve-horizon+1;required-preprovisioned-chaff-request-stream-frames-through-fin-"
            "fit-within-residual-normal-priority-stream-data-budget-after-higher-priority-due-"
            "application-stream-frames-at-each-positive-outgoing-horizon-start"
        ),
        "cells_per_nonzero_incoming_component": RECEIVER_CONTINUATION_CELLS,
        "formula": ("adapted_incoming=symmetric_incoming+1-if-symmetric_incoming>0-else-0"),
        "parser_allowance_ceiling_bytes": PARSER_ALLOWANCE_CEILING_BYTES,
        "post_outgoing_loss_liveness_limitation": (
            "insufficient-peer-acknowledged-survivors-after-positive-outgoing-targets-resolve-"
            "hold-base-and-continuation-allocation;no-targetless-chaff-stream-retransmission-or-"
            "generic-loss-liveness-guarantee"
        ),
        "prefix_consumability_precondition": (
            "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-"
            "consumable"
        ),
        "provisioning_policy": (
            "fill-configured-chaff-stream-limit-before-due-molded-outgoing-actions"
        ),
        "raw_headroom_bytes_per_nonzero_incoming_component": raw_headroom,
        "release_policy": (
            "after-all-base-events-controller-requested-and-request-signals-observed;reserve-"
            "deterministic-peer-acknowledged-pristine-candidates-for-current-zero-outgoing-"
            "continuation-horizon-before-first-base-allocation-and-retain-each-until-"
            "corresponding-continuation-release-or-session-end;recompute-live-unconsumed-base-"
            "each-retry;extend-single-coalesced-positive-outstanding-header-blocked-stream-else-"
            "reserved-peer-acknowledged-stream;outstanding-at-or-below-parser-ceiling"
        ),
        "request_activation_policy": (
            "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-"
            "with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-"
            "acknowledged-under-molded-outgoing-cells"
        ),
        "request_prefix_delivery_precondition": (
            "before-each-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-"
            "chaff-request-survivors>=current-receiver-continuation-reserve-horizon+1"
        ),
        "resource_precondition": (
            "initial-chaff-selection-yields-known-valid-dependency-free-same-origin-resource-"
            "with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component"
        ),
        "reserve_policy": (
            "reserve-deterministic-acknowledged-pristine-candidates-for-current-zero-outgoing-"
            "continuation-horizon-before-first-base-allocation-of-each-nonzero-incoming-component"
        ),
        "reserve_lifecycle_policy": (
            "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-"
            "allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-"
            "for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;"
            "retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-"
            "corresponding-horizon-reserve-before-further-base-allocation"
        ),
    }


def minimum_weight_perfect_matching(
    envelopes: Mapping[str, ProfileEnvelope],
) -> tuple[tuple[str, str, int], ...]:
    names = tuple(sorted(envelopes))
    if not names or len(names) % 2:
        raise ValueError("Walkie-Talkie perfect matching requires an even workload count")
    costs = {
        (left, right): symmetric_mold_padding_cost(envelopes[left].bursts, envelopes[right].bursts)
        for index, left in enumerate(names)
        for right in names[index + 1 :]
    }

    def choose(remaining: tuple[str, ...]) -> tuple[int, tuple[tuple[str, str], ...]]:
        if not remaining:
            return 0, ()
        left = remaining[0]
        best: tuple[int, tuple[tuple[str, str], ...]] | None = None
        for index in range(1, len(remaining)):
            right = remaining[index]
            rest = remaining[1:index] + remaining[index + 1 :]
            rest_cost, rest_pairs = choose(rest)
            pairs = tuple(sorted(((left, right), *rest_pairs)))
            candidate = (costs[(left, right)] + rest_cost, pairs)
            if best is None or candidate < best:
                best = candidate
        assert best is not None
        return best

    _total, selected = choose(names)
    return tuple((left, right, costs[(left, right)]) for left, right in selected)


def _batch_pairs(
    segments: Sequence[tuple[str, int]], packet_size: int, *, batch_index: int, label: str
) -> list[BurstPair]:
    if (
        not segments
        or segments[0][0] != "outgoing"
        or not any(direction == "incoming" for direction, _ in segments)
    ):
        raise ValueError(
            f"Walkie-Talkie batch {batch_index} requires outgoing then incoming: {label}"
        )
    result: list[BurstPair] = []
    index = 0
    while index < len(segments):
        direction, outgoing_bytes = segments[index]
        if direction != "outgoing":
            raise ValueError(f"Walkie-Talkie batch direction transitions are malformed: {label}")
        incoming_bytes = 0
        if index + 1 < len(segments) and segments[index + 1][0] == "incoming":
            incoming_bytes = segments[index + 1][1]
            index += 1
        result.append(
            BurstPair(
                _packet_count(outgoing_bytes, packet_size),
                _packet_count(incoming_bytes, packet_size),
                False,
            )
        )
        index += 1
    final = result[-1]
    result[-1] = BurstPair(final.outgoing, final.incoming, True)
    return result


def _append_segment(
    segments: list[tuple[str, int]], direction: str, count: int, label: str
) -> None:
    existing = sum(value for candidate, value in segments if candidate == direction)
    if existing + count > MAX_U64:
        raise ValueError(f"Walkie-Talkie {direction} bytes exceed u64: {label}")
    if segments and segments[-1][0] == direction:
        segments[-1] = (direction, segments[-1][1] + count)
    else:
        segments.append((direction, count))


def _split_batches(bursts: Sequence[BurstPair], label: str) -> tuple[tuple[BurstPair, ...], ...]:
    result: list[tuple[BurstPair, ...]] = []
    current: list[BurstPair] = []
    for pair in bursts:
        checked = _validated_pair(pair, label)
        current.append(checked)
        if checked.batch_end:
            result.append(tuple(current))
            current = []
    if current:
        raise ValueError(f"Walkie-Talkie sequence has no terminal batch marker: {label}")
    return tuple(result)


def _validated_pair(pair: BurstPair, label: str) -> BurstPair:
    if (
        type(pair.outgoing) is not int
        or type(pair.incoming) is not int
        or type(pair.batch_end) is not bool
        or not 0 <= pair.outgoing <= MAX_U32
        or not 0 <= pair.incoming <= MAX_U32
        or pair.outgoing + pair.incoming == 0
    ):
        raise ValueError(f"Walkie-Talkie burst is invalid: {label}")
    return pair


def _total_packets(bursts: Sequence[BurstPair]) -> int:
    if not bursts:
        raise ValueError("Walkie-Talkie packet sequence must not be empty")
    _split_batches(bursts, "packet sequence")
    return sum(pair.outgoing + pair.incoming for pair in bursts)


def _stream_key(details: Mapping[str, object], label: str) -> tuple[int, int]:
    return (
        _uint(details.get("endpoint"), "endpoint", label),
        _uint(details.get("stream"), "stream", label),
    )


def _role(value: object, label: str) -> str:
    if value == "application":
        return "application"
    if isinstance(value, Mapping) and set(value) == {"chaff"}:
        return "chaff"
    raise ValueError(f"Walkie-Talkie stream role is invalid: {label}")


def _uint(value: object, field: str, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError(f"Walkie-Talkie {field} is not an unsigned integer: {label}")
    return value


def _positive_uint(value: object, field: str, label: str) -> int:
    result = _uint(value, field, label)
    if result == 0:
        raise ValueError(f"Walkie-Talkie {field} must be positive: {label}")
    return result


def _unique_range_bytes(ranges: Sequence[tuple[int, int]]) -> int:
    total = 0
    current_start: int | None = None
    current_end = 0
    for start, end in sorted(ranges):
        if current_start is None:
            current_start, current_end = start, end
        elif start <= current_end:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start
            current_start, current_end = start, end
    if current_start is not None:
        total += current_end - current_start
    return total


def _packet_count(byte_count: int, packet_size: int) -> int:
    return (byte_count + packet_size - 1) // packet_size


def _variation_json(envelope: ProfileEnvelope) -> dict[str, int]:
    return {
        "visit_count": envelope.visit_count,
        "varying_components": envelope.varying_components,
        "maximum_component_spread": envelope.maximum_component_spread,
    }


def _bursts_json(bursts: Sequence[BurstPair]) -> list[dict[str, int]]:
    return [{"outgoing": pair.outgoing, "incoming": pair.incoming} for pair in bursts]


def _batch_ends(bursts: Sequence[BurstPair]) -> list[int]:
    return [index for index, pair in enumerate(bursts) if pair.batch_end]
