"""Prospective, fixed TAM receive credit; historical campaigns remain unchanged."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

FIELD = "tamaraw_configuration_policy"
POLICY = "rapid-tamaraw-initial8192-owned-bootstrap-v1"
INPUT = "tamaraw-initial8192.toml"
INITIAL16_POLICY = "resource-study-tamaraw-initial16-owned-bootstrap-v1"
INITIAL16_NATIVE = "6e50096dbce397e3f4e7be88de17d75986da5dff"


def validate_policy(value: Any) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value not in (POLICY, INITIAL16_POLICY):
        raise ValueError("unknown fixed Tamaraw configuration policy")
    return value


def policy(value: Mapping[str, Any]) -> str | None:
    if FIELD not in value:
        return None
    if value[FIELD] is None:
        raise ValueError("explicit fixed Tamaraw configuration cannot be null")
    return validate_policy(value[FIELD])


def resolved_configuration(*, selected_policy: str = POLICY) -> dict[str, Any]:
    if validate_policy(selected_policy) is None:
        raise ValueError("a complete fixed Tamaraw configuration needs an explicit policy")
    return {
        "schema_version": 2, "control_interval_us": 5000,
        "initial_max_stream_data": 16 if selected_policy == INITIAL16_POLICY else 8192, "automatic_receive_window": 1048576,
        "max_chaff_streams": 5, "low_watermark": 1000000,
        "use_empty_resources": False, "max_stream_data_excess": 1000,
        "max_udp_payload_size": 1200, "drop_unsatisfied_events": False,
        "keep_alive_lead_time_us": 100000, "tail_wait_us": 0,
        "defense": {"kind": "tamaraw", "incoming_interval_us": 5000,
                    "outgoing_interval_us": 20000, "packet_size": 1200, "modulo": 100},
    }


def configuration_bytes(*, selected_policy: str = POLICY) -> bytes:
    value = resolved_configuration(selected_policy=selected_policy)
    lines = [f"{key} = {json.dumps(item)}" for key, item in value.items() if key != "defense"]
    lines += ["", "[defense]", *(f"{key} = {json.dumps(item)}" for key, item in value["defense"].items())]
    return ("\n".join(lines) + "\n").encode("ascii")


def configuration_sha256(*, selected_policy: str = POLICY) -> str:
    return hashlib.sha256(configuration_bytes(selected_policy=selected_policy)).hexdigest()


def validate_configuration(path: Path, *, selected_policy: str = POLICY) -> Path:
    path = Path(path)
    if (any(parent.is_symlink() for parent in (path, *path.parents))
        or not path.is_file() or path.read_bytes() != configuration_bytes(selected_policy=selected_policy)):
        raise ValueError("fixed Tamaraw configuration file differs from its complete declared settings")
    return path


def validate_run(run: Mapping[str, Any], *, selected_policy: str | None) -> None:
    if validate_policy(selected_policy) is None:
        return
    actual, expected = run.get("resolved_configuration"), resolved_configuration(selected_policy=selected_policy)
    if (not isinstance(actual, Mapping) or set(actual) != set(expected)
        or any(type(actual[key]) is not type(item) or actual[key] != item
               for key, item in expected.items())
        or not isinstance(actual["defense"], dict)
        or any(type(actual["defense"].get(key)) is not type(item)
               for key, item in expected["defense"].items())):
        raise ValueError("Native run changed the fixed Tamaraw configuration")


def validate_campaign(*, selected_policy: str | None, profile: str, defenses,
                      body_policy: str | None, qualification_compatibility=None) -> None:
    if validate_policy(selected_policy) is None:
        return
    if selected_policy == INITIAL16_POLICY:
        raise ValueError("initial16 is an explicit ResourceStudy condition, not a general campaign policy")
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
    if (profile != "research-1200" or len(defenses) != 1
        or defenses[0].kind != "tamaraw" or defenses[0].baseline
        or defenses[0].parameters_path is not None or defenses[0].schedule_path is not None
        or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY
        or qualification_compatibility is not None):
        raise ValueError("fixed Tamaraw configuration requires its own complete-delivery single-setting campaign")


def validate_prepared(prepared: Mapping[str, Any]) -> None:
    from .capture_acceptance_policy import (
        validate_tamaraw_preparation_policy, validate_terminal_primary_preparation_policy,
        TAMARAW_POLICY, TERMINAL_PRIMARY_POLICY,
    )
    preparation = prepared.get("preparation")
    if (not isinstance(preparation, Mapping)
        or validate_tamaraw_preparation_policy(preparation) != TAMARAW_POLICY
        or validate_terminal_primary_preparation_policy(preparation) != TERMINAL_PRIMARY_POLICY):
        raise ValueError("fixed Tamaraw requires the preserved full-graph owned-credit preparation policies")


def target_identity() -> dict[str, Any]:
    """A fixed target identity, without a measurement or old-epoch credit claim."""
    return {FIELD: POLICY, "resolved_configuration": resolved_configuration(),
            "configuration_sha256": configuration_sha256(),
            "initial_credit_scope": "every-manually-controlled-application-and-chaff-request-stream",
            "initial_credit_bytes_per_stream": 8192,
            "extra_parser_credit_ceiling_bytes": 1000,
            "historical_tamaraw_condition_carried": False,
            "paper_equivalent": False, "scientific_credit": False}


# Source-only Native163 inherited-condition extension. The original139
# INITIAL16_NATIVE, amendment and all original physics remain unchanged.
INHERITED163_TYPE = 'qcsd-Euronews-inherited-active16-Native163-preparation-intent-v1'
INHERITED163_HOST = 'www.euronews.com'
INHERITED163_NATIVE = 'b77d46df18565a46f494fca0e1fa5a4c37e4dd63'
INHERITED163_CLIENT = '5c7692e7804a37be532cf22bdee19681ec284190d1679ee2684a72d44bf49d3d'
INHERITED163_WORKLOAD = 'b952aa649b456eeb192888ae3ffb329902a4467499661f6dbdc292b8ee3ee406'
INHERITED163_BASIS_CANONICAL = '53f5d82357e0a4fca8cdfd0d7fc811118148220c6974bac01e195dd095c56de9'
INHERITED163_BASIS_ROLES = ('sha256:ea510876b9e898dbb275591fd0d0c64f6c2326c2dcbd3f9327ae2f147199e1a9',
                           'sha256:617717760b1587d486f51c1479c3994e1cba2bac49eca54144b05bb9f9ef2ead')


def inherited163_runtime_scope(runtime, hostname, workload_sha256):
    """Shape/scope gate only; original canonical/installed proof is separate.

    Existing163 images are measured engineering bases, not the new executing
    SDK. Current-source role overlays must genuinely produce a new canonical.
    No unknown images become authoritative merely by passing this predicate.
    """
    import re
    if type(runtime) is not dict or set(runtime) != {
            'canonical_sha256', 'collection_image_digest', 'prepare_image_digest',
            'client_sha256', 'platform', 'native_commit', 'source'}:
        return False
    source = runtime.get('source')
    empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    return (hostname == INHERITED163_HOST and workload_sha256 == INHERITED163_WORKLOAD
        and runtime['client_sha256'] == INHERITED163_CLIENT
        and runtime['native_commit'] == INHERITED163_NATIVE and runtime['platform'] == 'linux/arm64'
        and type(runtime['canonical_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}', runtime['canonical_sha256']) is not None
        and runtime['canonical_sha256'] != INHERITED163_BASIS_CANONICAL
        and all(type(runtime[k]) is str and re.fullmatch('sha256:[0-9a-f]{64}', runtime[k]) is not None
                for k in ('collection_image_digest', 'prepare_image_digest'))
        and runtime['collection_image_digest'] != runtime['prepare_image_digest']
        and not set((runtime['collection_image_digest'], runtime['prepare_image_digest'])) & set(INHERITED163_BASIS_ROLES)
        and type(source) is dict and set(source) == {'image_digest', 'lab_commit', 'lab_dirty',
            'lab_patch_sha256', 'neqo_commit', 'neqo_pinned_commit', 'neqo_dirty', 'neqo_patch_sha256'}
        and source['image_digest'] is None and source['lab_dirty'] is False and source['neqo_dirty'] is False
        and source['lab_patch_sha256'] == source['neqo_patch_sha256'] == empty
        and source['neqo_commit'] == source['neqo_pinned_commit'] == INHERITED163_NATIVE
        and type(source['lab_commit']) is str and re.fullmatch('[0-9a-f]{40}', source['lab_commit']) is not None
        and source['lab_commit'] != '3f97e4781883542c05dbd0228b424fe1770ad06b')


def inherited163_intent(prior, hostname):
    """Pure frozen-head projection; the live initializer checks actual head.

    This accepts only the already-admitted original139 active16 condition.
    It never projects8192 to16 or creates another methodology amendment.
    """
    from copy import deepcopy
    from . import resource_study_cohorts as c
    e = c._epochs()
    if (hostname != INHERITED163_HOST or type(prior) is not dict
            or prior.get('record_type') != c.ADMISSION or type(prior.get('sequence')) is not int
            or prior['sequence'] < 61 or type(prior.get('class_transition')) is not dict
            or hostname not in prior['class_transition'].get('class_selection', {}).get('selected_hostnames', [])):
        raise ValueError('Native163 inherited16 requires actual admitted selected50 Euronews condition')
    cells = [cell for cell in prior.get('cells', []) if (cell.get('hostname'), cell.get('mode')) == (hostname, 'tamaraw')]
    entries = [entry for entry in prior.get('cohorts', []) if (entry.get('hostname'), entry.get('mode')) == (hostname, 'tamaraw')]
    if len(cells) != 1 or len(entries) != 1:
        raise ValueError('Native163 inherited16 requires one active Euronews writer')
    cell, entry = cells[0], entries[0]
    c._t16_condition_sciences(entry)  # Original two-strata/member/history checks.
    writers = [m for m in entry['members'] if m['cohort_id'] == entry['writer']]
    if len(writers) != 1 or not c._same(writers[0]['cell'], cell) or writers[0]['frozen_accepted'] is not None:
        raise ValueError('Native163 inherited16 active writer/member differs')
    definition = cell['definition']
    science = deepcopy(definition)
    science.pop('native'); science.pop('ready'); science['network'].pop('mapping_sha256', None)
    if (cell['definition_sha256'] != e._sha(definition) or not c._same(science, entry['science'])
            or definition['native'] != ['de9dbeca2bc07e8b3f731818b2058c8100c815935a53efef4c0a84d25eb089ff',
                'linux/arm64', INITIAL16_NATIVE]
            or definition['ready'] is not True or science['workload_sha256'] != INHERITED163_WORKLOAD
            or not (len(science['urls']) == len(set(science['urls'])) == 20)
            or science['policies'].get(FIELD) != INITIAL16_POLICY
            or science['settings']['configuration_sha256'] != configuration_sha256(selected_policy=INITIAL16_POLICY)
            or science['settings']['resolved_configuration'] != resolved_configuration(selected_policy=INITIAL16_POLICY)
            or [science['settings']['timeout_seconds'], science['settings']['capture_seconds']] != [120, 180]):
        raise ValueError('Native163 inherited16 changes current139 science, workload or fixed condition')
    return {'record_type': INHERITED163_TYPE, 'schema_version': 1, 'hostname': hostname, 'mode': 'tamaraw',
        'policy': INITIAL16_POLICY, 'predecessor_admission_sha256': e._sha(prior),
        'previous_definition_sha256': cell['definition_sha256'], 'active_writer': entry['writer'],
        'active_science_sha256': e._sha(science), 'active_condition_sha256': e._sha(entry['condition_strata']),
        'workload_sha256': INHERITED163_WORKLOAD, 'native_commit': INHERITED163_NATIVE,
        'client_sha256': INHERITED163_CLIENT, 'engineering_basis_canonical_sha256': INHERITED163_BASIS_CANONICAL,
        'shared_quota': 400, 'scientific_credit': False}


def require_inherited163_intent(prior, intent):
    from .resource_study_cohorts import _same
    if type(intent) is not dict or not _same(intent, inherited163_intent(prior, intent.get('hostname'))):
        raise ValueError('Native163 inherited16 intent differs from exact active parent condition')
    return intent
