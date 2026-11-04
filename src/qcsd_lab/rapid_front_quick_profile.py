"""One prospective direct FRONT V5 / Lab50 profile, with portable client bytes.

The original canary owns its Source and qualification labels. A current profile
joins that closed Native setting to an actual current runtime; neither grants
measurement credit or changes historical Native818 profiles.
"""
from pathlib import Path

from . import front_fixed_configuration as native
from . import front_incoming_acceptance as incoming
from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY

PROFILE_TYPE = "qcsd-prospective-direct-quick-fixed-front-launch-profile-v3"
NATIVE = "d2c4ec0e7dcc358fb0915d7b09c9a9b91715da8c"


def selected(seed, mode):
    """Require both explicit choices; a runtime head alone is no authority."""
    if not isinstance(seed, dict):
        raise ValueError("quick FRONT setting must be a policy document")
    if native.FIELD not in seed and incoming.FIELD not in seed:
        return False
    if (mode != "front" or native.policy(seed) != native.POLICY
            or incoming.configured(seed, mode=mode) != incoming.POLICY
            or seed.get("application_body_identity_policy") != COMPLETE_APPLICATION_DELIVERY_POLICY):
        raise ValueError("quick FRONT requires its exact explicit V5/Lab50 setting")
    return True


def validate_readiness(seed, recipe, deep, source):
    if not selected(seed, "front"):
        raise ValueError("quick FRONT seed lacks its prospective setting")
    for value in (recipe, deep):
        if (native.policy(value) != native.POLICY
                or incoming.configured(value, mode="front") != incoming.POLICY
                or value.get("application_body_identity_policy") != COMPLETE_APPLICATION_DELIVERY_POLICY):
            raise ValueError("quick FRONT original readiness changes its explicit setting")
    if (source.get("neqo_commit") != NATIVE or source.get("neqo_pinned_commit") != NATIVE
            or deep.get("front_configuration_sha256") != native.CONFIGURATION_SHA256):
        raise ValueError("quick FRONT original readiness changes its Native/configuration")


def validate_campaign(campaign):
    if (not selected(campaign, "front") or campaign.get("profile") != "research-1200"
            or campaign.get("request_policies") != ["as-defined"]
            or campaign.get("defenses") != [{"name": "front", "kind": "front"}]):
        raise ValueError("quick FRONT campaign changes its complete fixed setting")


def validate_artifacts(runtime, *, context=None):
    """Bind every config/provenance copy before parameter-context substitution."""
    from . import rapid_lane_evidence as lanes
    native.validate_source_artifacts(runtime)
    for name in ("execution_root", "runtime_source_root", "module_root"):
        for relative, digest in ((native.CONFIGURATION_PATH, native.CONFIGURATION_SHA256),
                                 (native.PROVENANCE_PATH, native.PROVENANCE_SHA256)):
            path = Path(runtime[name]) / relative
            raw = lanes._read(path) if context is None else context.watch_file(path)
            if path.stat().st_mode & 0o7777 != 0o644 or lanes._sha(raw) != digest:
                raise ValueError("quick FRONT source/execution config/provenance changed")
