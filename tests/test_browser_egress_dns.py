from __future__ import annotations

import dataclasses
import struct

import dpkt
import pytest

from qcsd_lab.browser_egress_dns import (
    DNS_CONTROL_MAX_QUERY_BYTES,
    dns_control_nxdomain_response,
    parse_dns_control_query,
)

_NAME = "dns-control.browser-egress.test"


def _name_wire(name: str) -> bytes:
    labels = (bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return b"".join(labels) + b"\0"


def _query(
    *,
    name: str = _NAME,
    identifier: int = 0x1234,
    flags: int = 0x0100,
    qtype: int = 1,
    qclass: int = 1,
    counts: tuple[int, int, int, int] = (1, 0, 0, 0),
    tail: bytes = b"",
) -> bytes:
    return (
        struct.pack("!HHHHHH", identifier, flags, *counts)
        + _name_wire(name)
        + struct.pack("!HH", qtype, qclass)
        + tail
    )


def _opt(*, size: int = 1232, ttl: int = 0, data: bytes = b"") -> bytes:
    return b"\0" + struct.pack("!HHIH", 41, size, ttl, len(data)) + data


@pytest.mark.parametrize("identifier", [0, 1, 0xFFFF])
@pytest.mark.parametrize("qtype", [1, 28, 65, 255, 65280])
@pytest.mark.parametrize("flags", [0, 0x0100])
def test_response_retains_id_question_rd_and_has_only_zero_ttl_soa(
    identifier: int, qtype: int, flags: int
) -> None:
    request = _query(identifier=identifier, qtype=qtype, flags=flags)
    response = dns_control_nxdomain_response(request, hostname=_NAME)
    assert struct.unpack("!HHHHHH", response[:12]) == (
        identifier, 0x8403 | flags, 1, 0, 1, 0
    )
    assert response[12:len(request)] == request[12:]
    decoded = dpkt.dns.DNS(response)
    assert decoded.id == identifier
    assert decoded.qr == 1 and decoded.aa == 1 and decoded.rcode == 3
    assert decoded.ra == 0 and decoded.tc == 0
    assert decoded.qd[0].name == _NAME and decoded.qd[0].type == qtype
    assert not decoded.an and not decoded.ar and len(decoded.ns) == 1
    soa = decoded.ns[0]
    assert (soa.name, soa.type, soa.cls, soa.ttl) == ("browser-egress.test", 6, 1, 0)
    assert (soa.mname, soa.rname) == ("", "")
    assert (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum) == (1, 0, 0, 0, 0)
    assert len(response) < 512
    assert response == dns_control_nxdomain_response(request, hostname=_NAME)


def test_query_metadata_is_exact_and_immutable_and_preserves_case_in_response() -> None:
    request = _query(name="DnS-CoNtRoL.Browser-Egress.TEST", qtype=65)
    question = parse_dns_control_query(request, hostname=_NAME)
    assert (question.identifier, question.name, question.qtype, question.qclass) == (
        0x1234, _NAME, 65, 1
    )
    assert question.recursion_desired and not question.dnssec_ok
    assert question.edns_udp_payload_size is None
    assert question.question_wire == request[12:]
    with pytest.raises(dataclasses.FrozenInstanceError):
        question.name = "attacker.test"
    response = dns_control_nxdomain_response(request, hostname=_NAME)
    assert response[12:len(request)] == request[12:]


@pytest.mark.parametrize("size", [0, 511, 512, 1232, 4096, 65535])
@pytest.mark.parametrize("do", [False, True])
def test_valid_edns_query_gets_empty_opt_not_reflected_options(size: int, do: bool) -> None:
    options = struct.pack("!HH", 65001, 3) + b"abc" + struct.pack("!HH", 12, 4) + b"\0" * 4
    request = _query(counts=(1, 0, 0, 1), tail=_opt(
        size=size, ttl=0x8000 if do else 0, data=options
    ))
    metadata = parse_dns_control_query(request, hostname=_NAME)
    assert metadata.edns_udp_payload_size == size and metadata.dnssec_ok is do
    response = dns_control_nxdomain_response(request, hostname=_NAME)
    decoded = dpkt.dns.DNS(response)
    assert len(decoded.ar) == 1
    opt = decoded.ar[0]
    assert (opt.name, opt.type, opt.cls, opt.ttl, opt.rdata) == (
        "", 41, DNS_CONTROL_MAX_QUERY_BYTES, 0x8000 if do else 0, b""
    )
    assert b"abc" not in response and len(response) < 512


@pytest.mark.parametrize("hostname", [None, b"host.test", "", ".", "a..test", "A.test",
                                     "host.test.", "-a.test", "a-.test", "a_b.test",
                                     "a/b.test", "é.test", "a" * 64 + ".test",
                                     "a." * 127 + "a"])
def test_approved_hostname_must_be_exact_canonical_hostname(hostname: object) -> None:
    with pytest.raises(ValueError, match="canonical ASCII hostname"):
        dns_control_nxdomain_response(_query(), hostname=hostname)


@pytest.mark.parametrize("name", ["attacker.test", "x." + _NAME, _NAME + ".attacker.test"])
def test_no_response_for_an_unapproved_name(name: str) -> None:
    with pytest.raises(ValueError, match="approved hostname"):
        dns_control_nxdomain_response(_query(name=name), hostname=_NAME)


@pytest.mark.parametrize("flag", [1 << bit for bit in range(16) if bit != 8])
def test_rejects_response_opcode_reserved_and_unsupported_header_bits(flag: int) -> None:
    with pytest.raises(ValueError, match="header supports only"):
        dns_control_nxdomain_response(_query(flags=0x100 | flag), hostname=_NAME)


@pytest.mark.parametrize("counts", [(0, 0, 0, 0), (2, 0, 0, 0), (1, 1, 0, 0),
                                   (1, 0, 1, 0), (1, 0, 0, 2), (65535, 0, 0, 0)])
def test_rejects_additional_questions_answers_authorities_and_multiple_opt(counts) -> None:
    with pytest.raises(ValueError, match="one question"):
        dns_control_nxdomain_response(_query(counts=counts), hostname=_NAME)


@pytest.mark.parametrize("qtype", [0, 41, 249, 250, 251, 252, 253, 254])
def test_rejects_reserved_opt_and_transfer_meta_question_types(qtype: int) -> None:
    with pytest.raises(ValueError, match="ordinary nonzero QTYPE"):
        dns_control_nxdomain_response(_query(qtype=qtype), hostname=_NAME)


@pytest.mark.parametrize("qclass", [0, 3, 4, 254, 255, 65535])
def test_rejects_non_in_question_class(qclass: int) -> None:
    with pytest.raises(ValueError, match="IN class"):
        dns_control_nxdomain_response(_query(qclass=qclass), hostname=_NAME)


@pytest.mark.parametrize("message", [None, "query", bytearray(b"x" * 12), b"", b"x" * 11,
                                    b"x" * (DNS_CONTROL_MAX_QUERY_BYTES + 1)])
def test_wire_input_type_and_size_are_bounded(message: object) -> None:
    with pytest.raises(ValueError, match="wire bytes"):
        dns_control_nxdomain_response(message, hostname=_NAME)


@pytest.mark.parametrize("qname", [b"\0", b"\xc0\x0c", b"\x40", b"\xff", b"\x05abc",
                                 b"\x01\xff\0", b"\x03a_b\0", b"\x03a.b\0",
                                 b"\x03-a-\0", b"\x03a\0b\0"])
def test_rejects_empty_compressed_extended_and_malformed_qnames(qname: bytes) -> None:
    request = struct.pack("!HHHHHH", 1, 0x100, 1, 0, 0, 0) + qname
    with pytest.raises(ValueError, match="QNAME"):
        dns_control_nxdomain_response(request, hostname=_NAME)


def test_rejects_every_truncated_plain_question_and_opt_message() -> None:
    plain = _query()
    edns = _query(counts=(1, 0, 0, 1), tail=_opt(data=struct.pack("!HH", 12, 3) + b"abc"))
    for request in (plain, edns):
        for length in range(len(request)):
            with pytest.raises(ValueError):
                dns_control_nxdomain_response(request[:length], hostname=_NAME)


@pytest.mark.parametrize("tail", [b"\0", b"\0" * 12, _opt()])
def test_rejects_uncounted_trailing_data(tail: bytes) -> None:
    with pytest.raises(ValueError, match="trailing uncounted"):
        dns_control_nxdomain_response(_query(tail=tail), hostname=_NAME)


@pytest.mark.parametrize("tail", [
    b"\xc0\x0c" + _opt()[1:],
    b"\x01a\0" + _opt()[1:],
    b"\0" + struct.pack("!HHIH", 1, 1232, 0, 0),
    _opt(ttl=1), _opt(ttl=0x10000), _opt(ttl=0x1000000),
    _opt() + b"x", _opt() + _opt(),
    _opt(data=b"x"), _opt(data=b"xxx"),
    _opt(data=struct.pack("!HH", 12, 5) + b"xxxx"),
])
def test_rejects_invalid_opt_owner_type_version_flags_lengths_and_options(tail: bytes) -> None:
    with pytest.raises(ValueError, match="OPT|EDNS0"):
        dns_control_nxdomain_response(_query(counts=(1, 0, 0, 1), tail=tail), hostname=_NAME)


def test_accepts_exact_maximum_wire_name_without_oversized_response() -> None:
    name = ".".join(["a" * 63] * 3 + ["b" * 61])
    assert len(_name_wire(name)) == 255
    request = _query(name=name, counts=(1, 0, 0, 1), tail=_opt())
    response = dns_control_nxdomain_response(request, hostname=name)
    assert len(response) < 512
    assert dpkt.dns.DNS(response).qd[0].name == name


def test_rejects_wire_name_over_255_octets_even_when_each_label_is_valid() -> None:
    request = _query(name=".".join(["a" * 63] * 4))
    with pytest.raises(ValueError, match="255-octet wire limit"):
        dns_control_nxdomain_response(request, hostname=_NAME)


def test_single_label_control_uses_root_as_parent_soa_owner() -> None:
    response = dns_control_nxdomain_response(_query(name="control"), hostname="control")
    assert dpkt.dns.DNS(response).ns[0].name == ""


def test_maximum_query_with_well_framed_opaque_edns_padding_has_small_response() -> None:
    plain = _query()
    padding_size = DNS_CONTROL_MAX_QUERY_BYTES - len(plain) - 11 - 4
    request = _query(counts=(1, 0, 0, 1), tail=_opt(
        data=struct.pack("!HH", 12, padding_size) + b"\0" * padding_size
    ))
    assert len(request) == DNS_CONTROL_MAX_QUERY_BYTES
    response = dns_control_nxdomain_response(request, hostname=_NAME)
    assert len(response) < 512
