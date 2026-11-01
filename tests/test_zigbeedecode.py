import struct

import pytest

from killerbee.zigbeedecode import (
    ZigBeeNWKPacketParser, ZigBeeAPSPacketParser,
    ZBEE_NWK_FCF_EXT_DEST, ZBEE_NWK_FCF_EXT_SOURCE, ZBEE_NWK_FCF_MULTICAST,
    ZBEE_NWK_FCF_SOURCE_ROUTE, ZBEE_NWK_FCF_CMD,
    ZBEE_APS_FCF_DATA, ZBEE_APS_FCF_CMD, ZBEE_APS_FCF_ACK, ZBEE_APS_FCF_EXT_HEADER,
)


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
    assert chop[3] == b"\x1e" and chop[4] == b"\x55"
    assert chop[5:9] == [b"", b"", b"", b""]
    assert chop[9] == b"PL"
    assert b"".join(chop) == pkt
    assert p.hdrlen(pkt) == 8
    assert p.payloadlen(pkt) == 2


def test_nwk_ext_addrs_and_mcast():
    p = ZigBeeNWKPacketParser()
    fc = ZBEE_NWK_FCF_EXT_DEST | ZBEE_NWK_FCF_EXT_SOURCE | ZBEE_NWK_FCF_MULTICAST | ZBEE_NWK_FCF_CMD
    pkt = nwk(fc, b"D" * 8 + b"S" * 8 + b"\x09")
    chop = p.pktchop(pkt)
    assert chop[5] == b"D" * 8
    assert chop[6] == b"S" * 8
    assert chop[7] == b"\x09"
    assert chop[9] == b"PL"
    assert b"".join(chop) == pkt
    # 8 fixed + 8 + 8 + 1 multicast control byte
    assert p.hdrlen(pkt) == 25
    assert p.payloadlen(pkt) == 2


def test_nwk_ext_dest_only():
    p = ZigBeeNWKPacketParser()
    pkt = nwk(ZBEE_NWK_FCF_EXT_DEST, b"D" * 8)
    assert p.hdrlen(pkt) == 16
    assert p.payloadlen(pkt) == 2


def test_nwk_source_route():
    p = ZigBeeNWKPacketParser()
    pkt = nwk(ZBEE_NWK_FCF_SOURCE_ROUTE, b"\x02\x00\xaa\xbb\xcc\xdd")
    assert p.hdrlen(pkt) == 8 + 2 + 4
    assert p.payloadlen(pkt) == 2
    chop = p.pktchop(pkt)
    assert chop[8] == b"\x02\x00\xaa\xbb\xcc\xdd"
    assert chop[-1] == b"PL"
    assert b"".join(chop) == pkt


def test_nwk_source_route_with_mcast_and_addrs():
    p = ZigBeeNWKPacketParser()
    fc = ZBEE_NWK_FCF_SOURCE_ROUTE | ZBEE_NWK_FCF_MULTICAST | ZBEE_NWK_FCF_EXT_SOURCE
    pkt = nwk(fc, b"S" * 8 + b"\x09" + b"\x01\x00\xaa\xbb")
    chop = p.pktchop(pkt)
    assert chop[8] == b"\x01\x00\xaa\xbb"
    assert chop[-1] == b"PL"
    assert p.hdrlen(pkt) == len(pkt) - 2


# ---------------------------------------------------------------- APS
def aps(fcbyte, body=b"", tail=b""):
    return bytes([fcbyte]) + body + tail


def fc(ftype, mode=0, ext=False):
    return ftype | (mode << 2) | (0x80 if ext else 0)


# (frame type, delivery mode) -> field sizes: dst ep, group, cluster, profile, src ep
LAYOUTS = {
    (ZBEE_APS_FCF_DATA, 0): (1, 0, 2, 2, 1),
    (ZBEE_APS_FCF_DATA, 1): (0, 0, 2, 2, 1),
    (ZBEE_APS_FCF_DATA, 2): (1, 0, 2, 2, 1),
    (ZBEE_APS_FCF_DATA, 3): (0, 2, 2, 2, 1),
    (ZBEE_APS_FCF_CMD, 0): (0, 0, 0, 0, 0),
    (ZBEE_APS_FCF_CMD, 1): (0, 0, 0, 0, 0),
    (ZBEE_APS_FCF_CMD, 2): (0, 0, 0, 0, 0),
    (ZBEE_APS_FCF_CMD, 3): (0, 2, 0, 0, 0),
    (ZBEE_APS_FCF_ACK, 0): (1, 0, 2, 2, 1),
    (ZBEE_APS_FCF_ACK, 1): (1, 0, 2, 2, 1),
    (ZBEE_APS_FCF_ACK, 2): (1, 0, 2, 2, 1),
    (ZBEE_APS_FCF_ACK, 3): (1, 2, 2, 2, 1),
}


@pytest.mark.parametrize("ftype", [ZBEE_APS_FCF_DATA, ZBEE_APS_FCF_CMD, ZBEE_APS_FCF_ACK])
@pytest.mark.parametrize("mode", [0, 1, 2, 3])
def test_aps_type_mode_matrix(ftype, mode):
    p = ZigBeeAPSPacketParser()
    # distinct byte per position so each field can be identified
    body = bytes(range(0x10, 0x30))
    pkt = aps(fc(ftype, mode), body, b"")
    sizes = LAYOUTS[(ftype, mode)]
    chop = p.pktchop(pkt)
    assert len(chop) == 10
    assert chop[0] == bytes([fc(ftype, mode)])
    off = 0
    for i, size in enumerate(sizes):
        assert chop[1 + i] == body[off:off + size], i
        off += size
    assert chop[6] == body[off:off + 1]            # APS counter
    assert chop[7] == chop[8] == b""               # no extended header
    assert chop[9] == body[off + 1:]               # payload
    assert p.hdrlen(pkt) == 1 + sum(sizes) + 1
    assert p.payloadlen(pkt) == len(body) - sum(sizes) - 1
    assert b"".join(chop) == pkt


@pytest.mark.parametrize("ftype", [ZBEE_APS_FCF_DATA, ZBEE_APS_FCF_CMD, ZBEE_APS_FCF_ACK])
@pytest.mark.parametrize("mode", [0, 1, 2, 3])
def test_aps_delivery_mode_uses_bits_2_3(ftype, mode):
    """The delivery mode is (fc & 0x0c) >> 2, independent of the frame type bits."""
    p = ZigBeeAPSPacketParser()
    pkt = aps(fc(ftype, mode), bytes(range(1, 30)))
    assert p.hdrlen(pkt) == 2 + sum(LAYOUTS[(ftype, mode)])


def test_aps_data_unicast_fields():
    p = ZigBeeAPSPacketParser()
    pkt = aps(0x00, b"\x0a" + b"\x01\x02" + b"\x03\x04" + b"\x0b", b"\x05" + b"PAY")
    chop = p.pktchop(pkt)
    assert chop == [b"\x00", b"\x0a", b"", b"\x01\x02", b"\x03\x04", b"\x0b",
                    b"\x05", b"", b"", b"PAY"]
    assert p.hdrlen(pkt) == 8
    assert p.payloadlen(pkt) == 3


def test_aps_data_group_fields():
    p = ZigBeeAPSPacketParser()
    pkt = aps(fc(ZBEE_APS_FCF_DATA, 3), b"\xaa\xbb" + b"\x01\x02" + b"\x03\x04" + b"\x0b", b"\x05" + b"PAY")
    chop = p.pktchop(pkt)
    assert chop[1:6] == [b"", b"\xaa\xbb", b"\x01\x02", b"\x03\x04", b"\x0b"]
    assert chop[-1] == b"PAY"


def test_aps_unknown_frame_type():
    # frame type 3 is not handled: only FC + counter + payload consumed
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x03, 0x09]) + b"XXXX"
    assert p.pktchop(pkt)[-1] == b"XXXX"
    assert p.hdrlen(pkt) == 2


@pytest.mark.parametrize("ftype", [ZBEE_APS_FCF_DATA, ZBEE_APS_FCF_CMD, ZBEE_APS_FCF_ACK])
def test_aps_extended_header_fragmented(ftype):
    p = ZigBeeAPSPacketParser()
    sizes = LAYOUTS[(ftype, 0)]
    addr = bytes(range(0x40, 0x40 + sum(sizes)))
    pkt = aps(fc(ftype, 0, True), addr + b"\x05" + b"\x01\x07" + b"XXXX")
    chop = p.pktchop(pkt)
    assert chop[6] == b"\x05"
    assert chop[7] == b"\x01" and chop[8] == b"\x07"
    assert chop[9] == b"XXXX"
    assert p.hdrlen(pkt) == 1 + sum(sizes) + 1 + 2


def test_aps_extended_header_not_fragmented():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x80, 0x0a, 1, 2, 3, 4, 0x0b, 0x05, 0x00]) + b"XXXX"
    chop = p.pktchop(pkt)
    # FC, then unicast addressing, counter, then a zero fragmentation byte
    assert chop[7] == b"\x00" and chop[8] == b""
    assert chop[9] == b"XXXX"
    assert p.hdrlen(pkt) == 9


def test_aps_too_small():
    with pytest.raises(Exception):
        ZigBeeAPSPacketParser().pktchop(b"\x00\x01")


def test_aps_pktchop_bytes():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x00, 0xaa, 1, 2, 3, 4, 0xbb, 0x09]) + b"XX"
    assert p.pktchop(pkt)[-1] == b"XX"


def test_aps_hdrlen_bytes():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x00, 0xaa, 1, 2, 3, 4, 0xbb, 0x09]) + b"XX"
    assert p.hdrlen(pkt) == 8


def test_aps_payloadlen_bytes():
    p = ZigBeeAPSPacketParser()
    pkt = bytes([0x00, 0xaa, 1, 2, 3, 4, 0xbb, 0x09]) + b"XX"
    assert p.payloadlen(pkt) == 2
