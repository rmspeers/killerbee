import struct

import pytest
from Crypto.Cipher import AES

from killerbee.dot154decode import (
    DOT154_FCF_INTRA_PAN,
    DOT154_FCF_SEC_EN,
    BadKeyLength,
    BadPayloadLength,
    Dot154PacketParser,
    UnsupportedPacket,
)

KEY = bytes(range(16))
SA = bytes([1, 2, 3, 4, 5, 6, 7, 8])
DA = bytes([9, 10, 11, 12, 13, 14, 15, 16])


def fcf_bytes(ftype=1, sec=False, intra=True, daddr=3, saddr=3):
    v = ftype
    if sec:
        v |= DOT154_FCF_SEC_EN
    if intra:
        v |= DOT154_FCF_INTRA_PAN
    v |= daddr << 10
    v |= saddr << 14
    return struct.pack("<H", v)


def _pad16(b):
    return b + b"\x00" * (-len(b) % 16)


def secured_frame(key=KEY, corrupt_mic=False, seclevel=6, plain=b"\x42"):
    """Build a MAC-secured frame with an independent, from-the-spec CCM*
    (AES-ECB based) implementation, 8-byte MIC, 13-byte nonce."""
    hdr = fcf_bytes(sec=True) + b"\x07" + b"\x34\x12" + DA + SA
    ctr = b"\x10\x20\x30\x40"
    nonce = SA[::-1] + ctr[::-1] + bytes([seclevel])
    filler = b"\xaa"
    aux = bytes([seclevel]) + ctr + filler
    a = hdr + aux
    add = struct.pack(">H", len(a)) + a
    B = bytes([0x59]) + nonce + struct.pack(">H", len(plain)) + _pad16(add) + _pad16(plain)
    ecb = AES.new(key, AES.MODE_ECB)
    x = b"\x00" * 16
    for i in range(0, len(B), 16):
        blk = bytes(p ^ q for p, q in zip(x, B[i : i + 16]))
        x = ecb.encrypt(blk)
    T = x[:8]
    S0 = ecb.encrypt(b"\x01" + nonce + b"\x00\x00")
    c = b""
    for n in range((len(plain) + 15) // 16):
        S = ecb.encrypt(b"\x01" + nonce + struct.pack(">H", n + 1))
        c += bytes(p ^ q for p, q in zip(plain[n * 16 : (n + 1) * 16], S))
    U = bytes(t ^ s for t, s in zip(T, S0))
    if corrupt_mic:
        U = bytes([U[0] ^ 1]) + U[1:]
    return hdr + aux + c + U, plain


@pytest.fixture
def p():
    return Dot154PacketParser()


def test_hdrlen_variants(p):
    base = 3 + 2 + 2 + 2
    assert p.hdrlen(fcf_bytes(daddr=2, saddr=2, intra=True) + b"\x00" * 9) == 9
    assert p.hdrlen(fcf_bytes(daddr=3, saddr=2, intra=True) + b"\x00" * 20) == 15
    assert p.hdrlen(fcf_bytes(daddr=3, saddr=3, intra=True) + b"\x00" * 20) == 21
    assert p.hdrlen(fcf_bytes(daddr=2, saddr=2, intra=False) + b"\x00" * 20) == 11
    assert base == 9


def test_hdrlen_too_small(p):
    with pytest.raises(Exception):
        p.hdrlen(b"\x01\x02\x03")


def test_payloadlen(p):
    pkt = fcf_bytes(daddr=2, saddr=2) + b"\x00" * 7 + b"abcd"
    assert p.payloadlen(pkt) == 4 + 0


def test_pktchop_beacon(p):
    fcf = struct.pack("<H", 0)
    body = (
        b"\x05"
        + b"\xaa\xbb"
        + b"\xcc\xdd"
        + b"\xff\xcf"
        + b"\x00"
        + b"\x00"
        + b"\x00"
        + b"\x22"
        + b"\x84"
        + b"\x01" * 8
        + b"\x00\x00\x00"
        + b"\x09"
        + b"\xee"
    )
    chop = p.pktchop(
        fcf
        + b"\x05"
        + b"\xaa\xbb"
        + b"\xcc\xdd"
        + b"\xff\xcf\x00\x00\x00\x22\x84"
        + b"\x01" * 8
        + b"\x00\x00\x00\x09"
        + b"\xee"
    )
    assert chop[0] == fcf
    assert chop[1] == b"\x05"
    assert chop[4] == b"\xaa\xbb" and chop[5] == b"\xcc\xdd"
    assert chop[6][0] == b"\xff\xcf"
    assert chop[6][6] == b"\x01" * 8
    assert chop[6][8] == b"\x09"
    assert chop[7] == b"\xee"
    assert body


def test_pktchop_beacon_truncated(p):
    chop = p.pktchop(struct.pack("<H", 0) + b"\x05" + b"\xaa\xbb\xcc\xdd\xff")
    assert chop[0] == b"\x00\x00"


@pytest.mark.parametrize(
    "daddr,saddr,intra",
    [
        (3, 3, True),
        (2, 2, True),
        (2, 2, False),
        (0, 0, True),
        (3, 3, False),
        (3, 2, True),
        (2, 3, True),
        (0, 2, False),
        (2, 0, True),
    ],
)
def test_pktchop_data(p, daddr, saddr, intra):
    pkt = fcf_bytes(daddr=daddr, saddr=saddr, intra=intra) + b"\x09" + b"\x34\x12"
    pkt += b"D" * {3: 8, 2: 2, 0: 0}[daddr]
    if not intra:
        pkt += b"\x77\x77"
    pkt += b"S" * {3: 8, 2: 2, 0: 0}[saddr]
    pkt += b"PAYLOAD"
    chop = p.pktchop(pkt)
    assert chop[1] == b"\x09"
    assert chop[2] == b"\x34\x12"
    size = {3: 8, 2: 2, 0: 0}
    assert chop[3] == b"D" * size[daddr]
    assert chop[5] == b"S" * size[saddr]
    assert chop[7] == b"PAYLOAD"
    if not intra:
        assert chop[4] == b"\x77\x77"


def test_pktchop_no_payload(p):
    pkt = fcf_bytes(daddr=0, saddr=0) + b"\x01\x34\x12"
    assert p.pktchop(pkt)[7] == b""


def test_nonce_unsecured(p):
    pkt = fcf_bytes(sec=False) + b"\x00" * 30
    assert p.nonce(pkt) == b""


def test_nonce_secured(p):
    pkt, _ = secured_frame()
    n = p.nonce(pkt)
    assert n == SA[::-1] + b"\x40\x30\x20\x10" + b"\x06"


def test_decrypt_unsupported_level(p):
    pkt, _ = secured_frame(seclevel=5)
    with pytest.raises(UnsupportedPacket):
        p.decrypt(pkt, KEY)


def test_decrypt_bad_key(p):
    pkt, _ = secured_frame()
    with pytest.raises(BadKeyLength):
        p.decrypt(pkt, b"short")


def test_decrypt_short_payload(p):
    hdr = fcf_bytes(sec=True) + b"\x07" + b"\x34\x12" + DA + SA
    pkt = hdr + b"\x06" + b"\x00" * 5
    with pytest.raises(BadPayloadLength):
        p.decrypt(pkt, KEY)


def test_decrypt_valid(p):
    pkt, plain = secured_frame()
    assert p.decrypt(pkt, KEY) == plain


@pytest.mark.parametrize("n", [1, 15, 16, 17, 32, 33, 100])
def test_decrypt_multiblock_payloads(p, n):
    plain = bytes((i * 7 + 1) & 0xFF for i in range(n))
    pkt, _ = secured_frame(plain=plain)
    assert p.decrypt(pkt, KEY) == plain


def test_decrypt_wrong_key(p):
    pkt, _ = secured_frame()
    assert p.decrypt(pkt, bytes(16)) == b""


def test_decrypt_not_secured_frame(p):
    # security level byte looks right but frame security is not enabled
    pkt = fcf_bytes(sec=False) + b"\x07" + b"\x34\x12" + DA + SA + b"\x06" + b"\x00" * 20
    assert p.decrypt(pkt, KEY) == b""


def test_decrypt_bad_mic(p):
    pkt, _ = secured_frame(corrupt_mic=True)
    assert p.decrypt(pkt, KEY) == b""
