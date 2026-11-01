import struct

import pytest

from killerbee.zigbeedecode import (
    ZigBeeNWKPacketParser, ZigBeeAPSPacketParser,
    ZBEE_NWK_FCF_EXT_DEST, ZBEE_NWK_FCF_EXT_SOURCE, ZBEE_NWK_FCF_MULTICAST,
    ZBEE_NWK_FCF_SOURCE_ROUTE, ZBEE_NWK_FCF_CMD,
    ZBEE_APS_FCF_DATA, ZBEE_APS_FCF_CMD, ZBEE_APS_FCF_ACK, ZBEE_APS_FCF_EXT_HEADER,
)

PY3_ORD = ("py3 bug: parser calls ord() on an int obtained by indexing bytes "
           "(written for py2 str)")


class IdxBytes(bytes):
    """bytes whose integer indexing yields 1-byte bytes (like py2 str), which
    lets the py2-style ord(packet[i]) code paths be exercised under py3."""
    def __getitem__(self, i):
        r = bytes.__getitem__(self, i)
        if isinstance(i, int):
            return bytes([r])
        return r


# ---------------------------------------------------------------- NWK
def nwk(fc=0, tail=b"", payload=b"PL"):
    return (struct.pack("<H", fc) + b"\x01\x02" + b"\x03\x04" + b"\x1e\x55"
            + tail + payload)


def test_nwk_too_small():
    p = ZigBeeNWKPacketParser()
    with pytest.raises(Exception):
        p.pktchop(b"\x00" * 5)


def test_nwk_plain():
    p = ZigBeeNWKPacketParser()
    pkt = nwk()
    chop = p.pktchop(pkt)
    assert chop[0] == b"\x00\x00"
    assert chop[1:3] == [b"\x01\x02", b"\x03\x04"]
    assert chop[3] == 0x1e and chop[4] == 0x55
    assert chop[5:9] == ["", "", "", ""]
    assert chop[9] == b"PL"
    assert p.hdrlen(pkt) == 8
    assert p.payloadlen(pkt) == 2


def test_nwk_ext_addrs_and_mcast():
    p = ZigBeeNWKPacketParser()
    fc = ZBEE_NWK_FCF_EXT_DEST | ZBEE_NWK_FCF_EXT_SOURCE | ZBEE_NWK_FCF_MULTICAST | ZBEE_NWK_FCF_CMD
    pkt = nwk(fc, b"D" * 8 + b"S" * 8 + b"\x09")
    chop = p.pktchop(pkt)
    assert chop[5] == b"D" * 8
    assert chop[6] == b"S" * 8
    assert chop[7] == 9
    assert chop[9] == b"PL"
    assert p.hdrlen(pkt) == 24


def test_nwk_ext_dest_only():
    p = ZigBeeNWKPacketParser()
    pkt = nwk(ZBEE_NWK_FCF_EXT_DEST, b"D" * 8)
    assert p.hdrlen(pkt) == 16
    assert p.payloadlen(pkt) == 2


def test_nwk_source_route_hdrlen_py2style():
    p = ZigBeeNWKPacketParser()
    pkt = IdxBytes(nwk(ZBEE_NWK_FCF_SOURCE_ROUTE, b"\x02\x00\xaa\xbb\xcc\xdd"))
    # plen = 8 + ord(packet[8]) * 2 ... + 2
    assert p.hdrlen(pkt) == 8 + 4 + 2


@pytest.mark.xfail(strict=False, reason=PY3_ORD)
def test_nwk_source_route_hdrlen_bytes():
    p = ZigBeeNWKPacketParser()
    pkt = nwk(ZBEE_NWK_FCF_SOURCE_ROUTE, b"\x02\x00\xaa\xbb\xcc\xdd")
    assert p.hdrlen(pkt) == 14


@pytest.mark.xfail(strict=False,
                   reason="py3 bug: source-route pktchop does int + int + bytes "
                          "(packet[relaycount + relayindex + relaylist])")
def test_nwk_source_route_pktchop():
    p = ZigBeeNWKPacketParser()
    pkt = nwk(ZBEE_NWK_FCF_SOURCE_ROUTE, b"\x02\x00\xaa\xbb\xcc\xdd")
    chop = p.pktchop(pkt)
    assert chop[-1] == b"PL"


# ---------------------------------------------------------------- APS
def aps(fcbyte, body, tail=b""):
    return fcbyte.to_bytes(1, "little") + body + tail


def fc(ftype, mode=0, ext=False):
    # NOTE: parser computes mode as (fc & (0x0c >> 2)) == fc & 0x03 (precedence
    # quirk), so low bits double as frame type and delivery mode.
    return ftype | (mode << 2) | (0x80 if ext else 0)


@pytest.mark.parametrize("fcv,body", [
    (0x00, b"\x0a" + b"\x01\x02" + b"\x03\x04" + b"\x0b"),            # data
    (0x04, b"\x0a" + b"\x01\x02" + b"\x03\x04" + b"\x0b"),
    (0x08, b"\x0a" + b"\x01\x02" + b"\x03\x04" + b"\x0b"),
    (0x0c, b"\x0a" + b"\x01\x02" + b"\x03\x04" + b"\x0b"),
])
def test_aps_data_py2style(fcv, body):
    p = ZigBeeAPSPacketParser()
    pkt = IdxBytes(aps(fcv, body, b"\x05" + b"PAY"))
    chop = p.pktchop(pkt)
    assert chop[-1] == b"PAY" or chop[-1].endswith(b"PAY")
    assert p.hdrlen(pkt) >= 1


@pytest.mark.parametrize("fcv", [0x01, 0x05, 0x09, 0x0d, 0x02, 0x06, 0x0a, 0x0e,
                                 0x03, 0x07, 0x0b, 0x0f])
def test_aps_all_frame_types_py2style(fcv):
    p = ZigBeeAPSPacketParser()
    pkt = IdxBytes(bytes([fcv]) + bytes(range(1, 12)) + b"PAYLOAD")
    try:
        p.pktchop(pkt)
    except Exception:
        pass
    p.hdrlen(pkt)
    assert p.payloadlen(pkt) <= len(pkt)


class _ModeMask(int):
    """Stand-in for ZBEE_APS_FCF_DELIVERY_MODE.  The parser computes
    `ord(fc) & MASK >> 2`, which (operator precedence bug) is fc & 0x03 and so
    aliases delivery mode with frame type.  This object makes `MASK >> 2`
    behave as the intended bits 2-3 extraction so the per-mode branches run."""
    def __rshift__(self, n):
        class _M:
            def __rand__(self, other):
                return (other >> 2) & 3
        return _M()


@pytest.fixture
def intended_modes(monkeypatch):
    import killerbee.zigbeedecode as mod
    monkeypatch.setattr(mod, "ZBEE_APS_FCF_DELIVERY_MODE", _ModeMask(0x0c))


@pytest.mark.parametrize("ftype", [ZBEE_APS_FCF_DATA, ZBEE_APS_FCF_CMD, ZBEE_APS_FCF_ACK])
@pytest.mark.parametrize("mode", [0, 1, 2, 3])
@pytest.mark.parametrize("ext", [False, True])
def test_aps_type_mode_matrix(intended_modes, ftype, mode, ext):
    p = ZigBeeAPSPacketParser()
    pkt = IdxBytes(bytes([fc(ftype, mode, ext)]) + bytes(range(1, 20)) + b"PAYLOADXX")
    chop = p.pktchop(pkt)
    assert chop[0] == bytes([fc(ftype, mode, ext)])
    hl = p.hdrlen(pkt)
    assert hl >= 2
    assert p.payloadlen(pkt) == len(pkt) - hl


def test_aps_unknown_frame_type(intended_modes):
    # frame type 3 is not handled: only FC + counter + payload consumed
    p = ZigBeeAPSPacketParser()
    pkt = IdxBytes(bytes([0x03, 0x09]) + b"XXXX")
    assert p.pktchop(pkt)[-1] == b"XXXX"
    assert p.hdrlen(pkt) == 2


def test_aps_extended_header_zero_block(intended_modes):
    p = ZigBeeAPSPacketParser()
    # hdrlen compares packet[i] != 0x00; plain-bytes tail covered by xfail tests
    pkt = IdxBytes(bytes([0x81, 0x01, 0x02, 0x03]) + b"XXXXXXXX")
    assert p.hdrlen(pkt) > 2


def test_aps_too_small():
    with pytest.raises(Exception):
        ZigBeeAPSPacketParser().pktchop(b"\x00\x01")


@pytest.mark.xfail(strict=False, reason=PY3_ORD)
def test_aps_pktchop_bytes():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x00, 0xaa, 1, 2, 3, 4, 0xbb, 0x09]) + b"XX"
    assert p.pktchop(pkt)[-1] == b"XX"


@pytest.mark.xfail(strict=False, reason=PY3_ORD)
def test_aps_hdrlen_bytes():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x00, 0xaa, 1, 2, 3, 4, 0xbb, 0x09]) + b"XX"
    assert p.hdrlen(pkt) == 8


@pytest.mark.xfail(strict=False, reason=PY3_ORD)
def test_aps_payloadlen_bytes():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x00, 0xaa, 1, 2, 3, 4, 0xbb, 0x09]) + b"XX"
    assert p.payloadlen(pkt) == 2
