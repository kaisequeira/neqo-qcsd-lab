"""Bounded DNS wire handling for one isolated browser-control hostname.

This is not a resolver or a general authoritative server.  It accepts only one
uncompressed, single-question IN query for the explicitly supplied hostname,
with the RD header flag optionally set and at most one well-framed EDNS0 OPT.
Malformed or unsupported messages raise ``ValueError``; no reply is fabricated
for another name.  Callers must retain rejected traffic as failed evidence.

The response preserves the transaction ID and exact question, sets QR, AA and
NXDOMAIN, copies RD, and clears RA.  A zero-TTL/zero-MINIMUM parent-zone SOA
provides a non-cacheable negative answer without any address or referral.  Its
MNAME and RNAME are inert root-name placeholders for this isolated fixture.
An EDNS query receives an empty EDNS0 OPT, copying only DO, never option data.

Wire references: RFC 1035 sections 4.1.1--4.1.4, RFC 2308 sections 3 and 5,
and RFC 6891 sections 6.1 and 6.2.3.  DNSSEC validation, recursion, forwarding,
compression in requests, transfers and general zone service are not provided.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

_HEADER = struct.Struct("!HHHHHH")
_QUESTION = struct.Struct("!HH")
_RR_FIXED = struct.Struct("!HHIH")
_OPTION_HEADER = struct.Struct("!HH")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
DNS_CONTROL_MAX_QUERY_BYTES = 4096


@dataclass(frozen=True)
class DnsControlQuestion:
    """Validated metadata; ``question_wire`` retains the request's letter case."""

    identifier: int
    name: str
    qtype: int
    qclass: int
    recursion_desired: bool
    question_wire: bytes
    edns_udp_payload_size: int | None
    dnssec_ok: bool


def _approved_hostname(hostname: str) -> str:
    if (
        not isinstance(hostname, str)
        or not hostname
        or hostname != hostname.lower()
        or any(_HOST_LABEL.fullmatch(label) is None for label in hostname.split("."))
        or len(hostname) > 253
    ):
        raise ValueError("DNS control hostname must be an exact canonical ASCII hostname")
    return hostname


def _edns_query_tail(message: bytes, offset: int) -> tuple[int, bool]:
    # OPT has a literal root owner, not an arbitrary/compressed name.
    if len(message) - offset < 1 + _RR_FIXED.size or message[offset] != 0:
        raise ValueError("DNS control OPT owner or fixed header is invalid")
    rr_type, udp_size, ttl, rdlength = _RR_FIXED.unpack_from(message, offset + 1)
    if rr_type != 41 or ttl & ~0x8000:
        raise ValueError("DNS control requires EDNS0 with zero extended RCODE/reserved flags")
    offset += 1 + _RR_FIXED.size
    end = offset + rdlength
    if end != len(message):
        raise ValueError("DNS control OPT RDATA length does not close the message")
    while offset < end:
        if end - offset < _OPTION_HEADER.size:
            raise ValueError("DNS control OPT option header is truncated")
        _code, length = _OPTION_HEADER.unpack_from(message, offset)
        offset += _OPTION_HEADER.size
        if length > end - offset:
            raise ValueError("DNS control OPT option data is truncated")
        # Unknown option values are opaque; their framing is checked, and they
        # are never reflected in the response (RFC 6891 section 6.1.2).
        offset += length
    return udp_size, bool(ttl & 0x8000)


def parse_dns_control_query(message: bytes, *, hostname: str) -> DnsControlQuestion:
    """Parse the fixture's strict query subset, refusing any other hostname.

    Names match case-insensitively, as DNS requires; the configured hostname
    itself must be lowercase without a trailing dot.  QTYPE is retained, not
    inferred from transport or address family.  Only ordinary nonzero data
    question types (not OPT or transfer/meta-query types 249--254) are accepted.
    The caller can impose a narrower observed-QTYPE qualification policy.
    """

    approved = _approved_hostname(hostname)
    if (
        not isinstance(message, bytes)
        or not _HEADER.size <= len(message) <= DNS_CONTROL_MAX_QUERY_BYTES
    ):
        raise ValueError("DNS control query must contain 12--4096 wire bytes")
    identifier, flags, questions, answers, authorities, additionals = _HEADER.unpack_from(message)
    if flags & ~0x0100:
        raise ValueError("DNS control query header supports only the RD flag")
    if questions != 1 or answers != 0 or authorities != 0 or additionals not in {0, 1}:
        raise ValueError("DNS control requires one question and at most one OPT record")

    labels: list[str] = []
    offset = _HEADER.size
    while True:
        if offset >= len(message):
            raise ValueError("DNS control QNAME is truncated")
        length = message[offset]
        offset += 1
        if length == 0:
            break
        if length > 63:
            raise ValueError("DNS control QNAME compression or extended labels are unsupported")
        end = offset + length
        if end > len(message):
            raise ValueError("DNS control QNAME label is truncated")
        try:
            label = message[offset:end].decode("ascii").lower()
        except UnicodeDecodeError as error:
            raise ValueError("DNS control QNAME label is not ASCII") from error
        if _HOST_LABEL.fullmatch(label) is None:
            raise ValueError("DNS control QNAME label is not a hostname label")
        labels.append(label)
        offset = end
        if offset - _HEADER.size >= 255:
            raise ValueError("DNS control QNAME exceeds the 255-octet wire limit")
    if not labels or offset - _HEADER.size > 255:
        raise ValueError("DNS control QNAME is empty or exceeds the wire limit")
    name = ".".join(labels)
    if name != approved:
        raise ValueError("DNS control question does not match the approved hostname")
    if len(message) - offset < _QUESTION.size:
        raise ValueError("DNS control QTYPE/QCLASS is truncated")
    qtype, qclass = _QUESTION.unpack_from(message, offset)
    if qclass != 1 or qtype in {0, 41, 249, 250, 251, 252, 253, 254}:
        raise ValueError("DNS control question must have an ordinary nonzero QTYPE and IN class")
    offset += _QUESTION.size
    question_wire = message[_HEADER.size:offset]
    if additionals:
        edns_size, dnssec_ok = _edns_query_tail(message, offset)
    else:
        if offset != len(message):
            raise ValueError("DNS control query has trailing uncounted bytes")
        edns_size, dnssec_ok = None, False
    return DnsControlQuestion(
        identifier=identifier,
        name=name,
        qtype=qtype,
        qclass=qclass,
        recursion_desired=bool(flags & 0x0100),
        question_wire=question_wire,
        edns_udp_payload_size=edns_size,
        dnssec_ok=dnssec_ok,
    )


def dns_control_nxdomain_response(message: bytes, *, hostname: str) -> bytes:
    """Return a bounded, non-recursive NXDOMAIN for exactly the approved name.

    The SOA owner points to the question's parent suffix.  Its two root names,
    serial 1 and zero timers have no external dependencies.  A response fits
    within the original 512-byte DNS limit, even for a maximum-length QNAME;
    EDNS does not enlarge it with caller-controlled options or padding.
    """

    question = parse_dns_control_query(message, hostname=hostname)
    flags = 0x8403 | (0x0100 if question.recursion_desired else 0)
    header = _HEADER.pack(
        question.identifier, flags, 1, 0, 1, int(question.edns_udp_payload_size is not None)
    )
    parent_offset = _HEADER.size + 1 + question.question_wire[0]
    soa_owner = struct.pack("!H", 0xC000 | parent_offset)
    soa_rdata = b"\0\0" + struct.pack("!IIIII", 1, 0, 0, 0, 0)
    soa = soa_owner + _RR_FIXED.pack(6, 1, 0, len(soa_rdata)) + soa_rdata
    additional = b""
    if question.edns_udp_payload_size is not None:
        # This advertises the fixture's receive bound, not an echoed option or
        # a demand for a large response.  Every response is still <512 bytes.
        additional = b"\0" + _RR_FIXED.pack(
            41, DNS_CONTROL_MAX_QUERY_BYTES, 0x8000 if question.dnssec_ok else 0, 0
        )
    return header + question.question_wire + soa + additional
