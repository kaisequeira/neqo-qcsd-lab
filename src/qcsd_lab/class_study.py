"""Pure contracts for the ``classifier-multiorigin100-v1`` class study.

This module deliberately has no network, capture, or repository-artifact
dependencies.  It defines the prospective population, deterministic cohort
selection, campaign arithmetic, and hash-bound receipt format used by the
class-study coordinator.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

STUDY_ID = "classifier-multiorigin100-v1"
SUCCESSOR_STUDY_PREFIX = "classifier-multiorigin100-v2"
SUCCESSOR_GENERATION_MIN = 1
SUCCESSOR_GENERATION_MAX = 99
SUCCESSOR_IDENTITY_PREFIX_LENGTH = 12
CONTRACT_SCHEMA_VERSION = 1
RECEIPT_TYPE = "qcsd-class-study-cohort"
LAUNCH_UNIQUENESS_POLICY = "canonical-role-block-and-cohort-assembly-v1"

CANDIDATE_COUNT = 600
PILOT_COUNT = 120
FINAL_CLASS_COUNT = 100
RESERVE_COUNT = 20
CANDIDATES_PER_STRATUM = 120
PILOT_CLASSES_PER_STRATUM = 24
FINAL_CLASSES_PER_STRATUM = 20
RESERVES_PER_STRATUM = 4

FORMAL_BLOCK_COUNT = 10
FORMAL_VISITS_PER_BLOCK = 2
TRAIN_BLOCKS = tuple(range(1, 9))
VALIDATION_BLOCKS = (9,)
TEST_BLOCKS = (10,)

COMPATIBILITY_MODES = (
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
FORMAL_MODES = tuple(mode for mode in COMPATIBILITY_MODES if mode != "static")


def class_study_launch_identity(
    *,
    campaign_name: str,
    evidence_role: str,
    cohort_sha256: str,
    cohort_assembly_sha256: str,
    study_id: str = STUDY_ID,
) -> dict[str, str]:
    """Return the canonical cross-format first-launch uniqueness identity."""

    if not study_id or not campaign_name or evidence_role not in EVIDENCE_ROLES:
        raise ValueError("class-study launch identity is invalid")
    for digest in (cohort_sha256, cohort_assembly_sha256):
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("class-study launch identity digest is invalid")
    return {
        "study_id": study_id,
        "campaign_name": campaign_name,
        "evidence_role": evidence_role,
        "class_study_cohort_sha256": cohort_sha256,
        "class_study_cohort_assembly_sha256": cohort_assembly_sha256,
        # A formatting-only YAML change must not open another physical-launch
        # namespace. The exact campaign bytes remain a separate claim field.
        "uniqueness_policy": LAUNCH_UNIQUENESS_POLICY,
    }


def class_study_launch_key(**identity: str) -> str:
    expected = class_study_launch_identity(
        study_id=identity["study_id"],
        campaign_name=identity["campaign_name"],
        evidence_role=identity["evidence_role"],
        cohort_sha256=identity["class_study_cohort_sha256"],
        cohort_assembly_sha256=identity[
            "class_study_cohort_assembly_sha256"
        ],
    )
    if identity != expected:
        raise ValueError("class-study launch identity fields are invalid")
    return hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

# These are campaign evidence roles.  Qualification sets remain separately
# typed evidence inputs rather than classifier-campaign samples.
EVIDENCE_ROLES = (
    "pilot-fitting",
    "pilot-compatibility",
    "authoritative-fitting",
    "certification",
    "canary",
    "formal",
)
EXPORTABLE_EVIDENCE_ROLES = frozenset({"formal"})

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SUCCESSOR_STUDY_ID_RE = re.compile(
    rf"{re.escape(SUCCESSOR_STUDY_PREFIX)}-g(?P<generation>[0-9]{{2}})-"
    rf"(?P<identity>[0-9a-f]{{{SUCCESSOR_IDENTITY_PREFIX_LENGTH}}})\Z"
)
_CLASS_STUDY_CAMPAIGN_RE = re.compile(
    rf"(?P<study_id>(?:{re.escape(STUDY_ID)}|"
    rf"{re.escape(SUCCESSOR_STUDY_PREFIX)}-g[0-9]{{2}}-"
    rf"[0-9a-f]{{{SUCCESSOR_IDENTITY_PREFIX_LENGTH}}}))-"
    r"(?P<suffix>(?:pilot-fitting-1200|pilot-compatibility-1080-1200|"
    r"authoritative-fitting-(?:1200|2000-1200)|certification-900-1200|"
    r"(?:canary|formal)-(?:0[1-9]|10)-1200))\Z"
)


@dataclass(frozen=True)
class ClassStudyIdentity:
    """One exact base or hash-derived successor study identity."""

    study_id: str
    generation: int
    identity_prefix: str | None

    @property
    def successor(self) -> bool:
        return self.generation > 0


@dataclass(frozen=True)
class ClassStudyCampaignIdentity:
    """The study, evidence role, and optional block encoded by a campaign name."""

    name: str
    study_id: str
    evidence_role: str
    block: int | None


def parse_class_study_id(value: object) -> ClassStudyIdentity:
    """Parse the complete anchored class-study identity grammar.

    The only admitted identities are the frozen v1 identifier and generated
    v2 identifiers of the form ``v2-gNN-<12 lowercase hex>``.  The two-digit
    generation namespace is deliberately bounded so formatting cannot silently
    grow into a different grammar.
    """

    if not isinstance(value, str):
        raise ValueError("class-study identity is invalid")
    if value == STUDY_ID:
        return ClassStudyIdentity(STUDY_ID, 0, None)
    match = _SUCCESSOR_STUDY_ID_RE.fullmatch(value)
    if match is None:
        raise ValueError("class-study identity is invalid")
    generation = int(match.group("generation"))
    if not SUCCESSOR_GENERATION_MIN <= generation <= SUCCESSOR_GENERATION_MAX:
        raise ValueError("class-study successor generation is outside its ID bounds")
    return ClassStudyIdentity(value, generation, match.group("identity"))


def is_class_study_id(value: object) -> bool:
    """Return whether ``value`` is one complete admitted study identity."""

    try:
        parse_class_study_id(value)
    except ValueError:
        return False
    return True


def is_successor_study_id(value: object) -> bool:
    """Return whether ``value`` is one complete generated successor identity."""

    try:
        return parse_class_study_id(value).successor
    except ValueError:
        return False


def successor_study_id(*, generation: int, identity_sha256: str) -> str:
    """Build a successor identity without permitting formatting overflow."""

    if (
        type(generation) is not int
        or not SUCCESSOR_GENERATION_MIN <= generation <= SUCCESSOR_GENERATION_MAX
    ):
        raise ValueError("class-study successor generation is outside its ID bounds")
    if (
        not isinstance(identity_sha256, str)
        or _SHA256_RE.fullmatch(identity_sha256) is None
    ):
        raise ValueError("class-study successor decision identity digest is invalid")
    value = (
        f"{SUCCESSOR_STUDY_PREFIX}-g{generation:02d}-"
        f"{identity_sha256[:SUCCESSOR_IDENTITY_PREFIX_LENGTH]}"
    )
    parsed = parse_class_study_id(value)
    if (
        parsed.generation != generation
        or parsed.identity_prefix != identity_sha256[:SUCCESSOR_IDENTITY_PREFIX_LENGTH]
    ):
        raise AssertionError("generated class-study successor identity is inconsistent")
    return value


def parse_class_study_campaign_name(value: object) -> ClassStudyCampaignIdentity:
    """Parse one exact generated class-study campaign name."""

    if not isinstance(value, str):
        raise ValueError("class-study campaign name is invalid")
    match = _CLASS_STUDY_CAMPAIGN_RE.fullmatch(value)
    if match is None:
        raise ValueError("class-study campaign name is invalid")
    identity = parse_class_study_id(match.group("study_id"))
    suffix = match.group("suffix")
    if identity.successor:
        if suffix in {
            "pilot-fitting-1200",
            "pilot-compatibility-1080-1200",
            "authoritative-fitting-1200",
        }:
            raise ValueError("class-study successor campaign name is invalid")
    elif suffix == "authoritative-fitting-2000-1200":
        raise ValueError("class-study v1 campaign name is invalid")
    if suffix == "pilot-fitting-1200":
        role, block = "pilot-fitting", None
    elif suffix == "pilot-compatibility-1080-1200":
        role, block = "pilot-compatibility", None
    elif suffix.startswith("authoritative-fitting-"):
        role, block = "authoritative-fitting", None
    elif suffix == "certification-900-1200":
        role, block = "certification", None
    else:
        role, raw_block, _profile = suffix.split("-")
        block = int(raw_block)
    return ClassStudyCampaignIdentity(value, identity.study_id, role, block)


def class_study_id_from_campaign_name(value: object) -> str:
    """Return the study ID from one exact generated campaign name."""

    return parse_class_study_campaign_name(value).study_id


def is_class_study_campaign_name(value: object) -> bool:
    """Return whether ``value`` is one exact generated class campaign name."""

    try:
        parse_class_study_campaign_name(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class TrancoRankStratum:
    """One fixed, inclusive rank interval in the study sampling frame."""

    id: str
    minimum_rank: int
    maximum_rank: int

    def contains(self, rank: int) -> bool:
        return self.minimum_rank <= rank <= self.maximum_rank

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "minimum_rank": self.minimum_rank,
            "maximum_rank": self.maximum_rank,
        }


TRANCO_RANK_STRATA = (
    TrancoRankStratum("1-1000", 1, 1_000),
    TrancoRankStratum("1001-10000", 1_001, 10_000),
    TrancoRankStratum("10001-100000", 10_001, 100_000),
    TrancoRankStratum("100001-500000", 100_001, 500_000),
    TrancoRankStratum("500001-1000000", 500_001, 1_000_000),
)


@dataclass(frozen=True)
class ClassCandidate:
    """The only fields permitted to influence deterministic cohort selection."""

    candidate_id: str
    domain: str
    rank: int
    eligible: bool

    @property
    def stratum(self) -> TrancoRankStratum:
        return rank_stratum(self.rank)

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "domain": self.domain,
            "rank": self.rank,
            "stratum": self.stratum.id,
            "eligible": self.eligible,
        }


@dataclass(frozen=True)
class CohortSelection:
    """Deterministically ordered candidate, pilot, final, and reserve cohorts."""

    candidates: tuple[ClassCandidate, ...]
    pilot: tuple[ClassCandidate, ...]
    final: tuple[ClassCandidate, ...]
    reserves: tuple[ClassCandidate, ...]
    feasible_pairs: tuple[tuple[str, str], ...] | None
    matching: tuple[tuple[str, str], ...] | None

    def inventories(self) -> dict[str, list[str]]:
        return {
            "candidate": [candidate.candidate_id for candidate in self.candidates],
            "pilot": [candidate.candidate_id for candidate in self.pilot],
            "final": [candidate.candidate_id for candidate in self.final],
            "reserve": [candidate.candidate_id for candidate in self.reserves],
        }


def rank_stratum(rank: int) -> TrancoRankStratum:
    """Return the fixed study stratum containing one Tranco rank."""

    if not isinstance(rank, int) or isinstance(rank, bool):
        raise ValueError("Tranco rank must be an integer")
    for stratum in TRANCO_RANK_STRATA:
        if stratum.contains(rank):
            return stratum
    raise ValueError(f"Tranco rank is outside the study sampling frame: {rank}")


def canonical_domain(domain: str) -> str:
    """Return a stable ASCII domain, rejecting URL and alias spellings."""

    if not isinstance(domain, str) or not domain:
        raise ValueError("candidate domain must be a non-empty string")
    try:
        value = domain.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"candidate domain is not valid IDNA: {domain!r}") from error
    value = value.lower().rstrip(".")
    if domain != value:
        raise ValueError(f"candidate domain is not canonical: {domain!r}")
    if len(value) > 253 or "." not in value:
        raise ValueError(f"candidate domain is not registrable-shaped: {domain!r}")
    labels = value.split(".")
    if any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"candidate domain contains an invalid label: {domain!r}")
    return value


def validate_evidence_role(role: str) -> str:
    """Validate and return a class-study campaign evidence role."""

    if role not in EVIDENCE_ROLES:
        raise ValueError(f"unsupported class-study evidence role: {role!r}")
    return role


def deterministic_candidate_order(
    candidates: Iterable[ClassCandidate],
    *,
    tranco_list_sha256: str,
) -> tuple[ClassCandidate, ...]:
    """Order candidates by stratum and the preregistered Tranco-bound hash."""

    list_sha256 = _validate_sha256(tranco_list_sha256, label="Tranco list SHA-256")
    values = tuple(candidates)
    _validate_candidate_identities(values)
    stratum_position = {stratum.id: index for index, stratum in enumerate(TRANCO_RANK_STRATA)}

    def key(candidate: ClassCandidate) -> tuple[int, str, str, str]:
        digest = hashlib.sha256(
            f"{list_sha256}{STUDY_ID}{candidate.domain}".encode()
        ).hexdigest()
        return (
            stratum_position[candidate.stratum.id],
            digest,
            candidate.domain,
            candidate.candidate_id,
        )

    return tuple(sorted(values, key=key))


def select_cohort(
    candidates: Iterable[ClassCandidate],
    *,
    tranco_list_sha256: str,
    feasible_pairs: Iterable[Sequence[str]] | None = None,
) -> CohortSelection:
    """Select the exact 600/120/100/20 cohorts without outcome-derived scores.

    The first 24 hash-ordered eligible candidates in every stratum enter the
    pilot.  Without a pair graph, the first 20 become final classes.  With a
    pair graph, a deterministic search selects and perfectly pairs exactly 20
    pilot classes per stratum; the other four per stratum become reserves.
    """

    ordered = deterministic_candidate_order(
        candidates,
        tranco_list_sha256=tranco_list_sha256,
    )
    if len(ordered) != CANDIDATE_COUNT:
        raise ValueError(f"candidate inventory must contain exactly {CANDIDATE_COUNT} records")

    pilot: list[ClassCandidate] = []
    for stratum in TRANCO_RANK_STRATA:
        members = tuple(candidate for candidate in ordered if candidate.stratum == stratum)
        if len(members) != CANDIDATES_PER_STRATUM:
            raise ValueError(
                f"stratum {stratum.id} must contain exactly {CANDIDATES_PER_STRATUM} candidates"
            )
        eligible = tuple(candidate for candidate in members if candidate.eligible)
        if len(eligible) < PILOT_CLASSES_PER_STRATUM:
            raise ValueError(
                f"stratum {stratum.id} has {len(eligible)} eligible candidates; "
                f"{PILOT_CLASSES_PER_STRATUM} are required"
            )
        pilot.extend(eligible[:PILOT_CLASSES_PER_STRATUM])
    pilot_tuple = tuple(pilot)

    normalised_pairs = _normalise_feasible_pairs(feasible_pairs, ordered)
    if normalised_pairs is None:
        final = tuple(
            candidate
            for stratum in TRANCO_RANK_STRATA
            for candidate in (member for member in pilot_tuple if member.stratum == stratum)
        )
        final = tuple(
            candidate
            for stratum in TRANCO_RANK_STRATA
            for candidate in tuple(item for item in final if item.stratum == stratum)[
                :FINAL_CLASSES_PER_STRATUM
            ]
        )
        matching = None
    else:
        final, matching = _select_paired_final(pilot_tuple, normalised_pairs)

    final_ids = {candidate.candidate_id for candidate in final}
    reserves = tuple(
        candidate for candidate in pilot_tuple if candidate.candidate_id not in final_ids
    )
    selection = CohortSelection(
        candidates=ordered,
        pilot=pilot_tuple,
        final=final,
        reserves=reserves,
        feasible_pairs=normalised_pairs,
        matching=matching,
    )
    _validate_selection(selection)
    return selection


def campaign_sample_counts() -> dict[str, int]:
    """Return the approved study-stage execution counts."""

    return {
        "nine_mode_regression": 2 * len(COMPATIBILITY_MODES),
        "controlled_gate": 2 * 4 * 4 * 5,
        "pilot_fitting": PILOT_COUNT * 2 * 2,
        "pilot_full_qualification": PILOT_COUNT * 6,
        "pilot_compatibility": PILOT_COUNT * len(COMPATIBILITY_MODES),
        "authoritative_fitting": FINAL_CLASS_COUNT * 10 * 2,
        "final_full_qualification": FINAL_CLASS_COUNT * 6,
        "final_certification": FINAL_CLASS_COUNT * len(COMPATIBILITY_MODES),
        "per_block_canaries": FORMAL_BLOCK_COUNT * FINAL_CLASS_COUNT,
        "formal": (
            FORMAL_BLOCK_COUNT * FINAL_CLASS_COUNT * FORMAL_VISITS_PER_BLOCK * len(FORMAL_MODES)
        ),
    }


def formal_split_counts() -> dict[str, dict[str, Any]]:
    """Return temporal train/validation/test membership and exact sample counts."""

    split_blocks = {
        "train": TRAIN_BLOCKS,
        "validation": VALIDATION_BLOCKS,
        "test": TEST_BLOCKS,
    }
    return {
        name: {
            "blocks": blocks,
            "visits_per_class_mode": len(blocks) * FORMAL_VISITS_PER_BLOCK,
            "samples": (
                len(blocks) * FINAL_CLASS_COUNT * FORMAL_VISITS_PER_BLOCK * len(FORMAL_MODES)
            ),
        }
        for name, blocks in split_blocks.items()
    }


def build_study_receipt(
    candidates: Iterable[ClassCandidate],
    *,
    tranco_list_id: str,
    tranco_list_sha256: str,
    feasible_pairs: Iterable[Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Build a self-contained, hash-bound cohort-contract receipt."""

    if not isinstance(tranco_list_id, str) or not tranco_list_id.strip():
        raise ValueError("Tranco list ID must be a non-empty string")
    list_sha256 = _validate_sha256(tranco_list_sha256, label="Tranco list SHA-256")
    selection = select_cohort(
        candidates,
        tranco_list_sha256=list_sha256,
        feasible_pairs=feasible_pairs,
    )
    payload = _study_payload(
        selection,
        tranco_list_id=tranco_list_id,
        tranco_list_sha256=list_sha256,
    )
    return bind_receipt(payload, receipt_type=RECEIPT_TYPE)


def validate_study_receipt(value: Mapping[str, Any]) -> CohortSelection:
    """Fail closed on receipt tampering or any study-contract divergence."""

    payload = validate_hash_bound_receipt(value, expected_type=RECEIPT_TYPE)
    if payload.get("study_id") != STUDY_ID:
        raise ValueError("class-study receipt has the wrong study ID")
    tranco = payload.get("tranco")
    if not isinstance(tranco, Mapping):
        raise ValueError("class-study receipt is missing its Tranco binding")
    list_id = tranco.get("list_id")
    list_sha256 = tranco.get("list_sha256")
    if not isinstance(list_id, str) or not list_id.strip():
        raise ValueError("class-study receipt has an invalid Tranco list ID")
    if not isinstance(list_sha256, str):
        raise ValueError("class-study receipt has an invalid Tranco list SHA-256")

    candidate_values = payload.get("candidates")
    if not isinstance(candidate_values, list):
        raise ValueError("class-study receipt candidates must be a list")
    candidates = tuple(_candidate_from_dict(candidate) for candidate in candidate_values)

    pair_values = payload.get("feasible_pair_graph")
    if pair_values is not None and not isinstance(pair_values, list):
        raise ValueError("class-study feasible-pair graph must be a list or null")
    selection = select_cohort(
        candidates,
        tranco_list_sha256=list_sha256,
        feasible_pairs=pair_values,
    )
    expected = _study_payload(
        selection,
        tranco_list_id=list_id,
        tranco_list_sha256=list_sha256,
    )
    if payload != expected:
        raise ValueError("class-study receipt differs from the derived contract")
    return selection


def bind_receipt(
    payload: Mapping[str, Any],
    *,
    receipt_type: str,
) -> dict[str, Any]:
    """Wrap a JSON payload in the common class-study hash envelope."""

    if not isinstance(receipt_type, str) or not receipt_type:
        raise ValueError("receipt type must be a non-empty string")
    frozen_payload = json.loads(canonical_json_bytes(payload))
    if not isinstance(frozen_payload, dict):
        raise ValueError("receipt payload must be a JSON object")
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "receipt_type": receipt_type,
        "payload_sha256": canonical_json_sha256(frozen_payload),
        "payload": frozen_payload,
    }


def validate_hash_bound_receipt(
    value: Mapping[str, Any],
    *,
    expected_type: str | None = None,
) -> dict[str, Any]:
    """Validate the strict envelope and return a detached payload copy."""

    if not isinstance(value, Mapping):
        raise ValueError("receipt must be a JSON object")
    expected_keys = {"schema_version", "receipt_type", "payload_sha256", "payload"}
    if set(value) != expected_keys:
        raise ValueError("receipt envelope fields differ from the contract")
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version != CONTRACT_SCHEMA_VERSION:
        raise ValueError("receipt schema version is unsupported")
    receipt_type = value.get("receipt_type")
    if not isinstance(receipt_type, str) or not receipt_type:
        raise ValueError("receipt type is invalid")
    if expected_type is not None and receipt_type != expected_type:
        raise ValueError(f"receipt type must be {expected_type!r}")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("receipt payload must be a JSON object")
    digest = value.get("payload_sha256")
    if not isinstance(digest, str) or digest != canonical_json_sha256(payload):
        raise ValueError("receipt payload SHA-256 does not verify")
    detached = json.loads(canonical_json_bytes(payload))
    if not isinstance(detached, dict):  # pragma: no cover - guarded above
        raise ValueError("receipt payload must be a JSON object")
    return detached


def canonical_json_bytes(value: Any) -> bytes:
    """Encode canonical, presentation-stable JSON used by receipts and hashes."""

    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def canonical_json_sha256(value: Any) -> str:
    """Hash the exact canonical JSON representation of a value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def write_create_only_json(path: Path, value: Any) -> Path:
    """Durably publish canonical JSON without replacing any existing path."""

    destination = Path(os.path.abspath(path))
    parent = _regular_existing_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"create-only JSON already exists: {destination}")
    encoded = canonical_json_bytes(value)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "xb",
            dir=parent,
            prefix=f".{destination.name}.",
            suffix=".qcsd-tmp",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise FileExistsError(f"create-only JSON already exists: {destination}") from error
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def write_study_receipt(path: Path, value: Mapping[str, Any]) -> Path:
    """Validate and create a class-study receipt exactly once."""

    validate_study_receipt(value)
    return write_create_only_json(path, value)


def load_study_receipt(path: Path) -> tuple[dict[str, Any], CohortSelection]:
    """Read one regular receipt file and independently revalidate it."""

    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"class-study receipt is not a regular file: {source}")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"class-study receipt is not valid JSON: {source}") from error
    if not isinstance(value, dict):
        raise ValueError("class-study receipt must be a JSON object")
    return value, validate_study_receipt(value)


def _study_payload(
    selection: CohortSelection,
    *,
    tranco_list_id: str,
    tranco_list_sha256: str,
) -> dict[str, Any]:
    return {
        "study_id": STUDY_ID,
        "tranco": {
            "list_id": tranco_list_id,
            "list_sha256": tranco_list_sha256,
            "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
        },
        "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
        "selection_policy": {
            "candidate_fields": ["candidate_id", "domain", "rank", "eligible"],
            "eligibility_only": True,
            "optional_pair_graph_only": True,
            "per_stratum": {
                "candidate": CANDIDATES_PER_STRATUM,
                "pilot": PILOT_CLASSES_PER_STRATUM,
                "final": FINAL_CLASSES_PER_STRATUM,
                "reserve": RESERVES_PER_STRATUM,
            },
        },
        "candidates": [candidate.as_dict() for candidate in selection.candidates],
        "inventories": selection.inventories(),
        "feasible_pair_graph": (
            [list(pair) for pair in selection.feasible_pairs]
            if selection.feasible_pairs is not None
            else None
        ),
        "selected_perfect_matching": (
            [list(pair) for pair in selection.matching] if selection.matching is not None else None
        ),
        "modes": {
            "compatibility": list(COMPATIBILITY_MODES),
            "formal": list(FORMAL_MODES),
        },
        "evidence_roles": list(EVIDENCE_ROLES),
        "formal_protocol": {
            "block_count": FORMAL_BLOCK_COUNT,
            "visits_per_block": FORMAL_VISITS_PER_BLOCK,
            "train_blocks": list(TRAIN_BLOCKS),
            "validation_blocks": list(VALIDATION_BLOCKS),
            "test_blocks": list(TEST_BLOCKS),
            "split_counts": _jsonable_split_counts(),
        },
        "campaign_sample_counts": campaign_sample_counts(),
    }


def _jsonable_split_counts() -> dict[str, dict[str, Any]]:
    return {
        name: {**record, "blocks": list(record["blocks"])}
        for name, record in formal_split_counts().items()
    }


def _candidate_from_dict(value: Any) -> ClassCandidate:
    if not isinstance(value, Mapping):
        raise ValueError("class-study candidate entry must be an object")
    if set(value) != {"candidate_id", "domain", "rank", "stratum", "eligible"}:
        raise ValueError("class-study candidate fields differ from the contract")
    candidate_id = value.get("candidate_id")
    domain = value.get("domain")
    rank = value.get("rank")
    eligible = value.get("eligible")
    if not isinstance(candidate_id, str) or not isinstance(domain, str):
        raise ValueError("class-study candidate identity fields must be strings")
    if not isinstance(rank, int) or isinstance(rank, bool) or not isinstance(eligible, bool):
        raise ValueError("class-study candidate rank/eligibility fields are invalid")
    candidate = ClassCandidate(candidate_id, domain, rank, eligible)
    if value.get("stratum") != candidate.stratum.id:
        raise ValueError("class-study candidate has an incorrect rank stratum")
    return candidate


def _validate_candidate_identities(candidates: tuple[ClassCandidate, ...]) -> None:
    identifiers: set[str] = set()
    domains: set[str] = set()
    ranks: set[int] = set()
    for candidate in candidates:
        if not isinstance(candidate, ClassCandidate):
            raise ValueError("candidate inventory entries must be ClassCandidate values")
        if not _IDENTIFIER_RE.fullmatch(candidate.candidate_id):
            raise ValueError(f"candidate ID is invalid: {candidate.candidate_id!r}")
        canonical_domain(candidate.domain)
        rank_stratum(candidate.rank)
        if not isinstance(candidate.eligible, bool):
            raise ValueError("candidate eligibility must be boolean")
        if candidate.candidate_id in identifiers:
            raise ValueError(f"duplicate candidate ID: {candidate.candidate_id}")
        if candidate.domain in domains:
            raise ValueError(f"duplicate candidate domain: {candidate.domain}")
        if candidate.rank in ranks:
            raise ValueError(f"duplicate Tranco rank: {candidate.rank}")
        identifiers.add(candidate.candidate_id)
        domains.add(candidate.domain)
        ranks.add(candidate.rank)


def _normalise_feasible_pairs(
    feasible_pairs: Iterable[Sequence[str]] | None,
    candidates: tuple[ClassCandidate, ...],
) -> tuple[tuple[str, str], ...] | None:
    if feasible_pairs is None:
        return None
    order = {candidate.candidate_id: index for index, candidate in enumerate(candidates)}
    pairs: set[tuple[str, str]] = set()
    for raw_pair in feasible_pairs:
        if isinstance(raw_pair, (str, bytes)):
            raise ValueError("feasible-pair graph entries must contain two candidate IDs")
        pair = tuple(raw_pair)
        if len(pair) != 2 or any(not isinstance(item, str) for item in pair):
            raise ValueError("feasible-pair graph entries must contain two candidate IDs")
        left, right = pair
        if left == right:
            raise ValueError("feasible-pair graph cannot contain self-edges")
        if left not in order or right not in order:
            raise ValueError("feasible-pair graph references an unknown candidate")
        if order[left] > order[right]:
            left, right = right, left
        pairs.add((left, right))
    return tuple(sorted(pairs, key=lambda pair: (order[pair[0]], order[pair[1]])))


def _select_paired_final(
    pilot: tuple[ClassCandidate, ...],
    feasible_pairs: tuple[tuple[str, str], ...],
) -> tuple[tuple[ClassCandidate, ...], tuple[tuple[str, str], ...]]:
    order = {candidate.candidate_id: index for index, candidate in enumerate(pilot)}
    adjacency = [0] * len(pilot)
    for left, right in feasible_pairs:
        if left not in order or right not in order:
            continue
        left_index = order[left]
        right_index = order[right]
        adjacency[left_index] |= 1 << right_index
        adjacency[right_index] |= 1 << left_index

    stratum_indices = {stratum.id: index for index, stratum in enumerate(TRANCO_RANK_STRATA)}
    member_strata = tuple(stratum_indices[candidate.stratum.id] for candidate in pilot)
    stratum_masks = tuple(
        sum(1 << index for index, value in enumerate(member_strata) if value == stratum_index)
        for stratum_index in range(len(TRANCO_RANK_STRATA))
    )
    initial_quotas = (FINAL_CLASSES_PER_STRATUM,) * len(TRANCO_RANK_STRATA)
    initial_mask = (1 << len(pilot)) - 1

    @cache
    def solve(
        remaining: int,
        quotas: tuple[int, ...],
    ) -> tuple[tuple[int, int], ...] | None:
        if not any(quotas):
            return ()
        if sum(quotas) % 2:
            return None
        for stratum_index, quota in enumerate(quotas):
            if quota < 0 or (remaining & stratum_masks[stratum_index]).bit_count() < quota:
                return None
        if not remaining:
            return None

        first_bit = remaining & -remaining
        first = first_bit.bit_length() - 1
        first_stratum = member_strata[first]
        without_first = remaining ^ first_bit

        if quotas[first_stratum] > 0:
            partners = adjacency[first] & without_first
            while partners:
                partner_bit = partners & -partners
                partner = partner_bit.bit_length() - 1
                partner_stratum = member_strata[partner]
                if quotas[partner_stratum] > 0:
                    next_quotas = list(quotas)
                    next_quotas[first_stratum] -= 1
                    next_quotas[partner_stratum] -= 1
                    if min(next_quotas) >= 0:
                        suffix = solve(
                            without_first ^ partner_bit,
                            tuple(next_quotas),
                        )
                        if suffix is not None:
                            return ((first, partner), *suffix)
                partners ^= partner_bit

        # Selecting an earlier hash-ordered candidate is always attempted first;
        # skipping is legal only while its stratum still has spare pilot members.
        if (without_first & stratum_masks[first_stratum]).bit_count() >= quotas[first_stratum]:
            return solve(without_first, quotas)
        return None

    index_matching = solve(initial_mask, initial_quotas)
    if index_matching is None:
        raise ValueError("feasible-pair graph cannot select a perfect 20-per-stratum final cohort")
    selected_indices = {index for pair in index_matching for index in pair}
    final = tuple(candidate for index, candidate in enumerate(pilot) if index in selected_indices)
    matching = tuple(
        (pilot[left].candidate_id, pilot[right].candidate_id) for left, right in index_matching
    )
    return final, matching


def _validate_selection(selection: CohortSelection) -> None:
    inventories = {
        "candidate": selection.candidates,
        "pilot": selection.pilot,
        "final": selection.final,
        "reserve": selection.reserves,
    }
    expected_counts = {
        "candidate": CANDIDATE_COUNT,
        "pilot": PILOT_COUNT,
        "final": FINAL_CLASS_COUNT,
        "reserve": RESERVE_COUNT,
    }
    for name, values in inventories.items():
        if len(values) != expected_counts[name]:
            raise ValueError(f"{name} inventory has the wrong cardinality")
        if len({candidate.candidate_id for candidate in values}) != len(values):
            raise ValueError(f"{name} inventory contains duplicates")

    pilot_ids = {candidate.candidate_id for candidate in selection.pilot}
    final_ids = {candidate.candidate_id for candidate in selection.final}
    reserve_ids = {candidate.candidate_id for candidate in selection.reserves}
    if final_ids & reserve_ids or final_ids | reserve_ids != pilot_ids:
        raise ValueError("final and reserve inventories must partition the pilot")
    for stratum in TRANCO_RANK_STRATA:
        if sum(candidate.stratum == stratum for candidate in selection.pilot) != (
            PILOT_CLASSES_PER_STRATUM
        ):
            raise ValueError(f"pilot quota is incorrect for stratum {stratum.id}")
        if sum(candidate.stratum == stratum for candidate in selection.final) != (
            FINAL_CLASSES_PER_STRATUM
        ):
            raise ValueError(f"final quota is incorrect for stratum {stratum.id}")
        if sum(candidate.stratum == stratum for candidate in selection.reserves) != (
            RESERVES_PER_STRATUM
        ):
            raise ValueError(f"reserve quota is incorrect for stratum {stratum.id}")
    if (selection.feasible_pairs is None) != (selection.matching is None):
        raise ValueError("pair graph and selected matching must either both be present or absent")
    if selection.matching is not None:
        graph = {frozenset(pair) for pair in selection.feasible_pairs or ()}
        matched = [candidate_id for pair in selection.matching for candidate_id in pair]
        if len(matched) != FINAL_CLASS_COUNT or set(matched) != final_ids:
            raise ValueError("selected matching does not cover the final cohort exactly once")
        if any(frozenset(pair) not in graph for pair in selection.matching):
            raise ValueError("selected matching contains an infeasible edge")


def _validate_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _regular_existing_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"create-only JSON parent contains a symbolic link: {current}")
    if not absolute.is_dir():
        raise ValueError(f"create-only JSON parent must exist: {absolute}")
    return absolute
