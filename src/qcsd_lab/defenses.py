"""Canonical defence identities and paper-adaptation metadata.

This is the single source used by plotting, reports, and machine fidelity
records.  Keeping the scientific declaration here prevents the human and
machine views of one adaptation from drifting.
"""

from __future__ import annotations

from dataclasses import dataclass


DEFENSE_ORDER = (
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
DEFENSE_RUNTIME_KINDS = {
    "undefended": "none",
    "static": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}
RUNTIME_KIND_DEFENSES = {
    runtime_kind: defense for defense, runtime_kind in DEFENSE_RUNTIME_KINDS.items()
}


def is_canonical_defense_suite(entries: object) -> bool:
    """Check stable public identity, runtime binding, and sole baseline."""

    if not isinstance(entries, (list, tuple)) or len(entries) != len(DEFENSE_ORDER):
        return False
    for expected_name, entry in zip(DEFENSE_ORDER, entries, strict=True):
        if isinstance(entry, dict):
            name = entry.get("name")
            kind = entry.get("kind")
            baseline = entry.get("baseline")
        else:
            name = getattr(entry, "name", None)
            kind = getattr(entry, "kind", None)
            baseline = getattr(entry, "baseline", None)
        if (
            name != expected_name
            or kind != DEFENSE_RUNTIME_KINDS[expected_name]
            or baseline is not (expected_name == "undefended")
        ):
            return False
    return True


@dataclass(frozen=True)
class DefenseAdaptation:
    label: str
    preserved_invariants: tuple[str, ...]
    exact_client_mechanisms: tuple[str, ...]
    qcsd_approximations: tuple[str, ...]
    unavailable_peer_properties: tuple[str, ...]
    validation_signal: str
    expected_interpretation: str
    paper_references: tuple[str, ...]
    implementation_status: str = "validated"


DEFENSE_ADAPTATIONS = {
    "undefended": DefenseAdaptation(
        label="Undefended",
        preserved_invariants=("no padding or scheduling invariant",),
        exact_client_mechanisms=("ordinary Neqo HTTP/3",),
        qcsd_approximations=(),
        unavailable_peer_properties=(),
        validation_signal="Response equality and direct trace.",
        expected_interpretation="QUIC baseline.",
        paper_references=(),
    ),
    "static": DefenseAdaptation(
        label="Static",
        preserved_invariants=("fixed signed packet schedule",),
        exact_client_mechanisms=("PING+PADDING", "STREAM release"),
        qcsd_approximations=("incoming slots use receiver credit and reviewed chaff",),
        unavailable_peer_properties=("server-side fixed schedule",),
        validation_signal="Exact slots, misses, and response equality.",
        expected_interpretation="Schedule feasibility in QUIC.",
        paper_references=("QCSD fixed-schedule operational baseline",),
    ),
    "front": DefenseAdaptation(
        label="FRONT",
        preserved_invariants=("seeded front-loaded Rayleigh padding times",),
        exact_client_mechanisms=("client-egress PING+PADDING",),
        qcsd_approximations=("incoming events use receiver credit and reviewed chaff",),
        unavailable_peer_properties=("cooperating server padding controller",),
        validation_signal="Seed goldens, direct bytes, and terminal slots.",
        expected_interpretation="Whether front loading survives client-only migration.",
        paper_references=(
            "Gong and Wang, Zero-delay Lightweight Defenses against Website "
            "Fingerprinting, USENIX Security 2020",
        ),
    ),
    "tamaraw": DefenseAdaptation(
        label="Tamaraw",
        preserved_invariants=("constant directional rates", "terminal modulo padding"),
        exact_client_mechanisms=("STREAM release", "client-egress PING+PADDING"),
        qcsd_approximations=("incoming rate uses receiver credit and reviewed chaff",),
        unavailable_peer_properties=("cooperating server scheduler",),
        validation_signal="Rate/modulo goldens, response equality, and tail.",
        expected_interpretation="Cost of rigid timing under QUIC control constraints.",
        paper_references=(
            "Cai et al., A Systematic Approach to Developing and Evaluating Website "
            "Fingerprinting Defenses, ACM CCS 2014, doi:10.1145/2660267.2660362",
        ),
    ),
    "traffic-morphing": DefenseAdaptation(
        label="Traffic Morphing",
        preserved_invariants=(
            "train-frozen workload-bound source-to-decoy size matrix",
            "padding-only upward transformation",
        ),
        exact_client_mechanisms=(
            "same-datagram client 1-RTT PADDING",
            "PING for non-ack-eliciting growth",
        ),
        qcsd_approximations=(
            "aggregate ingress target realization with receiver credit and reviewed chaff",
        ),
        unavailable_peer_properties=("conditional server-packet morphing",),
        validation_signal="Matrix distance, bypasses, received cover, shortfall, and direct PCAP.",
        expected_interpretation="Which size-distribution targets remain reachable.",
        paper_references=(
            "Wright, Coull, and Monrose, Traffic Morphing: An Efficient Defense Against "
            "Statistical Traffic Analysis, NDSS 2009",
        ),
    ),
    "wtf-pad": DefenseAdaptation(
        label="WTF-PAD",
        preserved_invariants=(
            "silent/burst/gap automaton",
            "consumable histogram tokens and infinity transitions",
        ),
        exact_client_mechanisms=("timer-driven client-egress PING+PADDING",),
        qcsd_approximations=("desired incoming events request receiver credit and reviewed chaff",),
        unavailable_peer_properties=("server-side adaptive-padding automaton",),
        validation_signal="Token/state goldens, lag, received cover, shortfall, and guard.",
        expected_interpretation="Whether adaptive timing transfers without peer cooperation.",
        paper_references=(
            "Juarez et al., Toward an Efficient Website Fingerprinting Defense, ESORICS 2016",
        ),
    ),
    "walkie-talkie": DefenseAdaptation(
        label="Walkie-Talkie",
        preserved_invariants=(
            "symmetric element-wise maximum burst mould",
            "global application half duplex",
        ),
        exact_client_mechanisms=("global request batches", "in-packet client padding"),
        qcsd_approximations=(
            "incoming cells use HTTP/3-consumed application and reviewed-chaff raw "
            "request-stream offsets",
        ),
        unavailable_peer_properties=(
            "cooperating half-duplex server",
            "Tor fixed-cell transport",
        ),
        validation_signal=(
            "Application request-STREAM crossing proof, per-burst mould distance, shortfall, "
            "delay, and no timeout success."
        ),
        expected_interpretation="Where burst moulding conflicts with QUIC multiplexing.",
        paper_references=(
            "Wang and Goldberg, Walkie-Talkie: An Efficient Defense Against Passive "
            "Website Fingerprinting Attacks, USENIX Security 2017",
        ),
    ),
    "buflo": DefenseAdaptation(
        label="BuFLO",
        preserved_invariants=(
            "fixed inter-packet interval",
            "fixed packet-size target",
            "minimum transmission duration",
        ),
        exact_client_mechanisms=(
            "paced STREAM release",
            "client-egress PING+PADDING",
        ),
        qcsd_approximations=(
            "incoming slots use receiver credit and response-qualified chaff",
            "paper packet-length parameters are mapped to QUIC UDP payload targets",
            "a finite event cap is a QCSD safety guard",
        ),
        unavailable_peer_properties=(
            "cooperating server-side BuFLO scheduler",
            "scheduled server datagram timing and size; incoming cells are client receive-credit/chaff attempts",
            "the paper's TCP packet-length accounting model",
        ),
        validation_signal=(
            "Reference-oracle equality, exact interval/size/minimum-duration goldens, "
            "guard status, response equality, direct PCAP, and controlled congestion tests."
        ),
        expected_interpretation=(
            "A client-only QUIC adaptation that remains non-paper-equivalent; its implementation "
            "status stays candidate until the versioned study validation gates pass."
        ),
        paper_references=(
            "Dyer et al., Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis "
            "Countermeasures Fail, IEEE Symposium on Security and Privacy 2012",
        ),
        implementation_status="candidate",
    ),
    "cs-buflo": DefenseAdaptation(
        label="CS-BuFLO",
        preserved_invariants=(
            "congestion-sensitive inter-packet interval",
            "power-of-two adaptation boundaries",
            "CTSP total-size and CPSP payload-size padding treatments",
            "quiet-time completion rule",
        ),
        exact_client_mechanisms=(
            "paced STREAM release",
            "client-egress PING+PADDING",
        ),
        qcsd_approximations=(
            "incoming slots use receiver credit and response-qualified chaff",
            "paper TCP write and wire sizes are mapped to QUIC UDP payload targets",
            "a finite event cap is a QCSD safety guard",
        ),
        unavailable_peer_properties=(
            "cooperating server-side CS-BuFLO controller",
            "scheduled server datagram timing and size; incoming cells are client receive-credit/chaff attempts",
            "the paper's modified OpenSSH/TCP congestion observations",
        ),
        validation_signal=(
            "Reference-oracle equality, CTSP/CPSP separation, rate-boundary and quiet-time "
            "goldens, guard status, response equality, direct PCAP, and netem congestion tests."
        ),
        expected_interpretation=(
            "Client-only QUIC CTSP/CPSP ablations that remain non-paper-equivalent; their "
            "implementation status stays candidate until the versioned study validation gates pass."
        ),
        paper_references=(
            "Cai et al., CS-BuFLO: A Congestion Sensitive Website Fingerprinting Defense, "
            "ACM WPES 2014",
        ),
        implementation_status="candidate",
    ),
}

DEFENSE_LABELS = {defense: adaptation.label for defense, adaptation in DEFENSE_ADAPTATIONS.items()}
DEFENSE_VARIANT_LABELS = {
    "cs-buflo-ctsp": "CS-BuFLO (CTSP)",
    "cs-buflo-cpsp": "CS-BuFLO (CPSP)",
}


def canonical_defense(value: str) -> str:
    """Return the stable public name for a runtime defence identifier."""

    normalized = value.lower().replace("_", "-")
    return "undefended" if normalized in {"none", "undefended"} else normalized


def defense_from_runtime_identity(name: object, runtime_kind: object) -> str:
    """Resolve scientific identity from the runtime, with alias consistency."""

    if not isinstance(name, str) or not name.strip():
        raise ValueError("defense name is missing")
    if not isinstance(runtime_kind, str) or runtime_kind not in RUNTIME_KIND_DEFENSES:
        raise ValueError(f"unsupported defense runtime kind: {runtime_kind}")
    defense = RUNTIME_KIND_DEFENSES[runtime_kind]
    normalized_name = canonical_defense(name)
    if (
        normalized_name in DEFENSE_RUNTIME_KINDS
        and DEFENSE_RUNTIME_KINDS[normalized_name] != runtime_kind
    ):
        raise ValueError(f"defense name {name!r} is not bound to runtime kind {runtime_kind!r}")
    return defense


def adaptation_table_rows() -> tuple[tuple[str, str, str, str, str, str, str], ...]:
    """Return report-ready rows in the append-only canonical selection order."""

    def sentence(parts: tuple[str, ...]) -> str:
        text = "; ".join(parts)
        return text[:1].upper() + text[1:] + "."

    rows = []
    for defense in DEFENSE_ORDER:
        adaptation = DEFENSE_ADAPTATIONS[defense]
        rows.append(
            (
                adaptation.label,
                sentence(adaptation.preserved_invariants),
                sentence(adaptation.exact_client_mechanisms),
                (
                    sentence(
                        (
                            *adaptation.qcsd_approximations,
                            *adaptation.unavailable_peer_properties,
                        )
                    )
                    if adaptation.qcsd_approximations or adaptation.unavailable_peer_properties
                    else "None."
                ),
                adaptation.validation_signal,
                adaptation.expected_interpretation,
                adaptation.implementation_status,
            )
        )
    return tuple(rows)
