from __future__ import annotations


UDP_PAYLOAD_CEILING_BY_PROFILE = {
    "live": 1_200,
    "published": 1_450,
}


def udp_payload_ceiling(profile: object) -> int | None:
    """Return the canonical UDP-payload ceiling for one QCSD profile."""

    return UDP_PAYLOAD_CEILING_BY_PROFILE.get(profile) if isinstance(profile, str) else None
