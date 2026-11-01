import unittest
import struct
import argparse
import os
from scapy.all import *
from killerbee.scapy_extensions import * 

import pytest


@pytest.mark.usefixtures("apimote_env")
class TestKbScapyExt(unittest.TestCase):
    def test_kbdev(self):
        kbdev()
        self.assertTrue(True)

    def test_kbsendp(self):
        devstring = os.environ['APIMOTE_DEVSTRING']
        packet = Dot15d4(struct.pack("<80s", (b'\x01'*80)))
        kbsendp(packet)
        self.assertTrue(True)

    def _test_kbsrp(self):
        devstring = os.environ['APIMOTE_DEVSTRING']
        packet = Dot15d4(struct.pack("<80s", (b'\x01'*80)))
        kbsrp(packet)
        self.assertTrue(True)
        
    def _test_kbsrp1(self):
        devstring = os.environ['APIMOTE_DEVSTRING']
        packet = Dot15d4(struct.pack("<80s", (b'\x01'*80)))
        kbsrp1(packet)
        self.assertTrue(True)
        
    def _test_kbsniff(self):
        devstring = os.environ['APIMOTE_DEVSTRING']
        kbsniff(channel=11)
        self.assertTrue(True)

    def _test_kbrdpcap(self):
        path_to_file = "./tests/fixtures/test_pcap.pcap"

        packets = kbrdpcap(path_to_file)
        self.assertEqual(b'\x08\x07\x06\x05\x04\x03\x02\x01', packets[0].dest_addr.to_bytes(8, 'big'))

    def _test_kbwrpcap(self):
        path_to_file = "./tests/fixtures/test_pcap.pcap"
        path_to_file_out = "./tests/fixtures/test_pcap_out.pcap"

        packets = kbrdpcap(path_to_file)
        self.assertEqual(b'\x08\x07\x06\x05\x04\x03\x02\x01', packets[0].dest_addr.to_bytes(8, 'big'))

        kbwrpcap(path_to_file_out, packets)
        packets = kbrdpcap(path_to_file_out)
        
        self.assertEqual(b'\x08\x07\x06\x05\x04\x03\x02\x01', packets[0].dest_addr.to_bytes(8, 'big'))

        os.remove(path_to_file_out)

    #daintree deprecated
    def _test_kbrddain(self):
        self.assertFalse(False)
    def _test_kbwrdain(self):
        self.assertFalse(False)

    # TODO get binary keyfile and encrypted/decrypted packets
    def _test_kbkeysearch(self):
        self.assertTrue(True)

    def _test_kbgetnetworkkey(self):
        path_to_file = "./tests/fixtures/test_pcap.pcap"
        network_key =  b"\xe4\x2f\xc8\x5f\x9b\xaf\x5f\x4f\xb5\x8e\x6a\x1d\xbd\x2a\x13\x45"
        packets = kbrdpcap(path_to_file)
        recovered_key = kbgetnetworkkey(packets)
        print(recovered_key)

        self.assertEqual(network_key, recovered_key)

    #TODO figure out how to test
    def _test_kbtshark(self):
        self.assertTrue(True)

    def test_kbrandmac(self):
        self.assertEqual(8, len(kbrandmac()))
        self.assertEqual(12, len(kbrandmac(12)))
        self.assertEqual(6, len(kbrandmac(6)))
        self.assertEqual(3, len(kbrandmac(3)))

    @pytest.mark.usefixtures("py_zigbee_crypt")
    def test_kbdecrypt(self):
        network_key =  b"\xe4\x2f\xc8\x5f\x9b\xaf\x5f\x4f\xb5\x8e\x6a\x1d\xbd\x2a\x13\x45"
        encrypted_packet = b'a\x88\xe0|F\x00\x00s\xc5H"\x00\x00s\xc5\x1e\x00(\xee\xee\x00\x00\x8a\xdc\x1a\xfe\xff\x81\x8eX\x00\xcf\x8c\xce6\x16\xe7\x8cA)\x87\x12\x84#2\xd8_y\xe7~\x8d\xfb\xf8'
        plaintext_data = b'@\x01\x01\x05\x04\x01\x01Y\x01\x00\x00\x00\x041234\x00'
        scapy_packet = Dot15d4(encrypted_packet)

        decrypted_data = kbdecrypt(scapy_packet, network_key)

        self.assertEqual(plaintext_data, decrypted_data.build())

    @pytest.mark.usefixtures("py_zigbee_crypt")
    def test_kbencrypt(self):
        network_key =  b"\xe4\x2f\xc8\x5f\x9b\xaf\x5f\x4f\xb5\x8e\x6a\x1d\xbd\x2a\x13\x45"
        encrypted_packet = b'a\x88\xe0|F\x00\x00s\xc5H"\x00\x00s\xc5\x1e\x00(\xee\xee\x00\x00\x8a\xdc\x1a\xfe\xff\x81\x8eX\x00\xcf\x8c\xce6\x16\xe7\x8cA)\x87\x12\x84#2\xd8_y\xe7~\x8d\xfb\xf8'
        data = b'@\x01\x01\x05\x04\x01\x01Y\x01\x00\x00\x00\x041234\x00'
        packet = b'a\x88\xe0|F\x00\x00s\xc5H"\x00\x00s\xc5\x1e\x00(\xee\xee\x00\x00\x8a\xdc\x1a\xfe\xff\x81\x8eX\x00@\x01\x01\x05\x04\x01\x01Y\x01\x00\x00\x00\x041234\x00'
        encrypted_data = kbencrypt(Dot15d4(packet), data, network_key)

        self.assertEqual(encrypted_data.build(), encrypted_packet)

    def test_kbgetmiclen(self):
        self.assertEqual(0, kbgetmiclen(DOT154_CRYPT_NONE))
        self.assertEqual(4, kbgetmiclen(DOT154_CRYPT_MIC32))
        self.assertEqual(8, kbgetmiclen(DOT154_CRYPT_MIC64))
        self.assertEqual(16, kbgetmiclen(DOT154_CRYPT_MIC128))
        self.assertEqual(0, kbgetmiclen(DOT154_CRYPT_ENC))
        self.assertEqual(4, kbgetmiclen(DOT154_CRYPT_ENC_MIC32))
        self.assertEqual(8, kbgetmiclen(DOT154_CRYPT_ENC_MIC64))
        self.assertEqual(16, kbgetmiclen(DOT154_CRYPT_ENC_MIC128))
       
    def _test_kbgetpanid(self):
        self.assertTrue(True)
    



ENC_PKT = b'a\x88\xe0|F\x00\x00s\xc5H"\x00\x00s\xc5\x1e\x00(\xee\xee\x00\x00\x8a\xdc\x1a\xfe\xff\x81\x8eX\x00\xcf\x8c\xce6\x16\xe7\x8cA)\x87\x12\x84#2\xd8_y\xe7~\x8d\xfb\xf8'
NWK_KEY = b"\xe4\x2f\xc8\x5f\x9b\xaf\x5f\x4f\xb5\x8e\x6a\x1d\xbd\x2a\x13\x45"


def _frame_with_fcs(raw=ENC_PKT):
    from killerbee.kbutils import makeFCS
    return raw + makeFCS(raw)


@pytest.fixture
def fake_dev(apimote_env):
    """Return the fake serial port (or None with real hardware)."""
    if apimote_env != "/dev/ttyFAKE0":
        pytest.skip("needs fake device")
    from conftest import FakeGoodFETSerial

    class Handle:
        @staticmethod
        def port():
            return FakeGoodFETSerial.last
    return Handle


class TestKbScapyRadio:
    @pytest.fixture(autouse=True)
    def _short_pnext(self, monkeypatch):
        """__kb_recv calls kb.pnext() with the default 100s timeout; shorten it."""
        orig = KillerBee.pnext
        monkeypatch.setattr(KillerBee, "pnext",
                            lambda self, timeout=100: orig(self, timeout=0.01))

    def _queue(self, fake_dev, frames):
        # the fake is created when KillerBee() opens, so patch the class queue
        from conftest import FakeGoodFETSerial
        orig = FakeGoodFETSerial.__init__

        def init(self, *a, **kw):
            orig(self, *a, **kw)
            for f in frames:
                self.queue_packet(bytes([len(f)]) + f)
        FakeGoodFETSerial.__init__ = init
        return orig

    def test_kbsniff_count(self, fake_dev):
        from conftest import FakeGoodFETSerial
        orig = self._queue(fake_dev, [_frame_with_fcs(), _frame_with_fcs()])
        try:
            seen = []
            res = kbsniff(channel=11, count=2, prn=seen.append, verbose=2)
        finally:
            FakeGoodFETSerial.__init__ = orig
        assert len(res) == 2
        assert len(seen) == 2

    def test_kbsniff_lfilter_and_stop_filter(self, fake_dev):
        from conftest import FakeGoodFETSerial
        orig = self._queue(fake_dev, [_frame_with_fcs()] * 3)
        try:
            calls = []
            res = kbsniff(channel=11, lfilter=lambda p: len(calls) or not calls.append(1) and False,
                          stop_filter=lambda p: True, page=0)
        finally:
            FakeGoodFETSerial.__init__ = orig
        assert len(res) == 1

    def test_kbsniff_timeout(self, fake_dev):
        res = kbsniff(channel=11, timeout=0.05, store=0)
        assert len(res) == 0

    def test_kbsniff_iface_instance(self, fake_dev):
        kb = KillerBee()
        res = kbsniff(iface=kb, timeout=0.01)
        assert len(res) == 0

    def test_kbsniff_iface_string(self, fake_dev):
        res = kbsniff(iface="/dev/ttyFAKE0", channel=12, timeout=0.01)
        assert len(res) == 0

    def test_kbtshark(self, fake_dev):
        from conftest import FakeGoodFETSerial
        orig = self._queue(fake_dev, [_frame_with_fcs()])
        try:
            shown = []
            res = kbtshark(count=1, store=1)
        finally:
            FakeGoodFETSerial.__init__ = orig
        assert len(res) == 1

    def test_kbsendp_variants(self, fake_dev):
        kb = KillerBee()
        pkt = Dot15d4(b'\x01' * 20)
        kbsendp(pkt, channel=15, count=2, verbose=1, iface=kb)
        fake = fake_dev.port()
        assert len(fake.tx_packets) == 2
        kbsendp(pkt, iface="/dev/ttyFAKE0", count=1, inter=0, realtime=1, verbose=0)
        # an already-FCS packet is sent as is
        kbsendp(Dot15d4FCS(_frame_with_fcs()), count=1)

    @pytest.mark.xfail(strict=False, run=False, reason="__kb_send never decrements a positive 'loop', so loop=N>0 sends forever")
    def test_kbsendp_loop(self, fake_dev):
        pkt = Dot15d4(b'\x01' * 20)
        kbsendp(pkt, loop=1, verbose=0)

    def test_kbsrp_and_kbsrp1(self, fake_dev):
        from conftest import FakeGoodFETSerial
        orig = self._queue(fake_dev, [_frame_with_fcs(), _frame_with_fcs()])
        try:
            pkt = Dot15d4(b'\x01' * 20)
            res = kbsrp(pkt, channel=11, count=1, verbose=1)
            assert len(res) == 1
            res = kbsrp1(pkt, channel=11, verbose=0)
            assert len(res) == 1
        finally:
            FakeGoodFETSerial.__init__ = orig

    def test_kbsrp_iface(self, fake_dev):
        kb = KillerBee()
        res = kbsrp(Dot15d4(b'\x01' * 20), iface=kb, timeout=0.01, count=0)
        assert len(res) == 0
        res = kbsrp(Dot15d4(b'\x01' * 20), iface="/dev/ttyFAKE0", timeout=0.01)
        assert len(res) == 0

    def test_send_keyboard_interrupt(self, fake_dev, monkeypatch):
        import killerbee.scapy_extensions as se
        kb = KillerBee()

        def boom(*a, **k):
            raise KeyboardInterrupt
        monkeypatch.setattr(kb, "inject", boom)
        n = getattr(se, "_%s__kb_send" % "x", None) or se.__dict__["__kb_send"]
        assert n(kb, Dot15d4(b'\x01' * 10), verbose=0) == 0

    def test_recv_keyboard_interrupt(self, fake_dev, monkeypatch):
        import killerbee.scapy_extensions as se
        kb = KillerBee()

        def boom(*a, **k):
            raise KeyboardInterrupt
        monkeypatch.setattr(kb, "pnext", boom)
        assert se.__dict__["__kb_recv"](kb) == []

    def test_send_str_and_list(self, fake_dev):
        import killerbee.scapy_extensions as se
        kb = KillerBee()
        send = se.__dict__["__kb_send"]
        assert send(kb, "abcdefgh", verbose=0, count=1) == 1
        assert send(kb, [Dot15d4(b'\x01' * 10)], verbose=1, count=1, realtime=1) == 1


class TestKbScapyFiles:
    def _write_pcap(self, path, frames):
        from killerbee import PcapDumper, DLT_IEEE802_15_4
        d = PcapDumper(DLT_IEEE802_15_4, str(path))
        for f in frames:
            d.pcap_dump(f)
        d.close()

    def test_rdpcap_wrpcap_roundtrip(self, tmp_path):
        src = tmp_path / "in.pcap"
        out = tmp_path / "out.pcap"
        f1, f2, f3 = (_frame_with_fcs(), _frame_with_fcs(b'\x41\x88\x01' + bytes(10)),
                      _frame_with_fcs(b'\x41\x88\x02' + bytes(10)))
        self._write_pcap(src, [f1, f2, f3])
        pkts = kbrdpcap(str(src))
        assert len(pkts) == 3
        assert len(kbrdpcap(str(src), count=2)) == 2
        assert len(kbrdpcap(str(src), skip=1)) == 2
        assert len(kbrdpcap(str(src), nofcs=True)) == 3
        kbwrpcap(str(out), pkts)
        again = kbrdpcap(str(out))
        assert [bytes(p) for p in again] == [bytes(p) for p in pkts]

    def test_rddain_wrdain(self, tmp_path):
        out = tmp_path / "out.dcf"
        pkts = [Dot15d4FCS(_frame_with_fcs()), Dot15d4FCS(_frame_with_fcs())]
        kbwrdain(str(out), pkts)
        res = kbrddain(str(out))
        assert len(res) == 2
        assert len(kbrddain(str(out), skip=1)) == 1
        assert len(kbrddain(str(out), count=1)) == 1

    def test_rddain_fixture_copy(self, tmp_path):
        import shutil
        dst = tmp_path / "read.dcf"
        shutil.copy(os.path.join(os.path.dirname(__file__), "fixtures", "test_dt_read.dcf"), dst)
        assert len(kbrddain(str(dst))) >= 1

    def test_kbkeysearch_not_encrypted(self):
        pkt = Dot15d4(b'\x01\x08\x01\x00\x00')
        with pytest.raises(Exception):
            kbkeysearch(pkt, "x" * 64, ispath=False)

    @pytest.mark.xfail(strict=False, reason="kbkeysearch uses py2 str semantics (Dot154PacketParser.decrypt on str keys)")
    def test_kbkeysearch_finds_key(self, tmp_path):
        keyfile = tmp_path / "blob.bin"
        keyfile.write_bytes(b"\x00" * 5 + NWK_KEY + b"\x00" * 40)
        pkt = Dot15d4(ENC_PKT)
        r = kbkeysearch(pkt, str(keyfile), ispath=True, skipfcs=False)
        assert r == ":".join("%02x" % b for b in NWK_KEY)

    def test_kbkeysearch_no_match(self, tmp_path):
        pkt = Dot15d4(b'\x61\x88\x01\x00\x00\x00\x00\x00\x00')
        try:
            r = kbkeysearch(pkt, "A" * 40, ispath=False)
        except Exception:
            pytest.xfail("kbkeysearch raises on py3 (bytes/str mix)")
        assert r is None

    def test_kbgetnetworkkey_no_key(self):
        assert kbgetnetworkkey([Dot15d4(ENC_PKT)]) == {}
        assert kbgetnetworkkey(Dot15d4(ENC_PKT)) == {}


class TestKbScapyCrypto:
    def test_kbdecrypt_errors(self, py_zigbee_crypt, caplog):
        conf.killerbee_nkey = None
        pkt = Dot15d4(ENC_PKT)
        assert kbdecrypt(pkt) is None            # no key configured
        assert kbdecrypt(pkt, b"short") is None  # bad key length
        assert kbdecrypt(Dot15d4(b'\x01\x08\x01\x00\x00'), NWK_KEY) is None  # no sec hdr

    def test_kbdecrypt_conf_key_and_miccheck(self, py_zigbee_crypt):
        conf.killerbee_nkey = NWK_KEY
        try:
            out = kbdecrypt(Dot15d4(ENC_PKT), verbose=3, doMicCheck=True)
        finally:
            conf.killerbee_nkey = None
        assert out[1] is True
        wrong = kbdecrypt(Dot15d4(ENC_PKT), b"\x00" * 16, doMicCheck=True)
        assert wrong[1] is False

    def test_kbdecrypt_no_crypto_module(self, monkeypatch):
        import sys
        monkeypatch.setitem(sys.modules, "zigbee_crypt", None)
        assert kbdecrypt(Dot15d4(ENC_PKT), NWK_KEY) is None
        assert kbencrypt(Dot15d4(ENC_PKT), b"x", NWK_KEY) is None

    def test_kbencrypt_errors(self, py_zigbee_crypt):
        conf.killerbee_nkey = None
        pkt = Dot15d4(ENC_PKT)
        assert kbencrypt(pkt, b"x") is None
        assert kbencrypt(pkt, b"x", b"short") is None
        assert kbencrypt(Dot15d4(b'\x01\x08\x01\x00\x00'), b"x", NWK_KEY) is None

    def test_kbencrypt_conf_key_verbose_packet_payload(self, py_zigbee_crypt):
        conf.killerbee_nkey = NWK_KEY
        try:
            pkt = Dot15d4(ENC_PKT)
            out = kbencrypt(pkt, Raw(b"hello"), verbose=3)
        finally:
            conf.killerbee_nkey = None
        assert out is not None

    def test_kbgetpanid(self):
        pkt = Dot15d4(ENC_PKT)
        panid, layer = kbgetpanid(pkt)
        assert panid is not None
        assert kbgetpanid(Raw(b"x")) == (None, None)

    def test_kbrandmac_and_kbdev(self, apimote_env, capsys):
        assert len(kbrandmac()) == 8
        kbdev()
        assert "Product String" in capsys.readouterr().out



class _Chop:
    """Fake zigbee parser returning py2-style (str) chopped fields."""
    def __init__(self, result):
        self.result = result

    def __call__(self):
        return self

    def pktchop(self, packet):
        return self.result


def _key_payload(cmd=5, ktype=1, size=35):
    key = "".join(chr(i) for i in range(16))
    body = chr(cmd) + chr(ktype) + key + "\x00" + "".join(chr(0x10 + i) for i in range(8)) \
        + "".join(chr(0x20 + i) for i in range(8))
    return (body + "\x00" * 40)[:max(size, 0)] if size < 35 else body


class TestKbGetNetworkKeyMocked:
    """kbgetnetworkkey relies on py2 str semantics in the zigbee parsers; the
    parsers are mocked here to exercise its branch logic."""

    def _run(self, monkeypatch, mac, nwk, aps):
        import killerbee.scapy_extensions as se
        monkeypatch.setattr(se, "Dot154PacketParser", _Chop(mac))
        monkeypatch.setattr(se, "ZigBeeNWKPacketParser", _Chop(nwk))
        monkeypatch.setattr(se, "ZigBeeAPSPacketParser", _Chop(aps))
        return kbgetnetworkkey([Dot15d4(ENC_PKT)])

    def test_found(self, monkeypatch):
        r = self._run(monkeypatch, ["x", "macpayload"], ["x", "nwkpayload"],
                      [chr(ZBEE_APS_FCF_CMD), _key_payload()])
        assert r["key"].startswith("0f:0e:0d")
        assert r["dst"].count(":") == 7 and r["src"].count(":") == 7

    @pytest.mark.parametrize("mac,nwk,aps", [
        ([None], ["x", "n"], ["a", "b"]),                                    # no mac payload
        (["x", "m"], [None], ["a", "b"]),                                    # no nwk payload
        (["x", "m"], ["x", "n"], None),                                      # no aps chop
        (["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_DATA), "p"]),             # not a cmd
        (["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_CMD | 0x04), "p"]),       # delivery mode != 0
        (["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_CMD | 0x20), "p"]),       # security (becomes 0x21 !=1 -> passes)
        (["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_CMD), "short"]),          # too short
        (["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_CMD), _key_payload(cmd=4)]),   # not transport key
        (["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_CMD), _key_payload(ktype=2)]),  # not nwk key
    ])
    def test_rejected(self, monkeypatch, mac, nwk, aps):
        assert self._run(monkeypatch, mac, nwk, aps) == {}

    def test_security_bit_exactly_one(self, monkeypatch):
        # (apsfc & 0x20) == 1 can never hold; documents the always-false check
        r = self._run(monkeypatch, ["x", "m"], ["x", "n"], [chr(ZBEE_APS_FCF_CMD | 0x20), _key_payload()])
        assert "key" in r


class TestKbSendRealtime:
    def test_realtime_pacing(self, apimote_env, monkeypatch):
        import time as _t
        import killerbee.scapy_extensions as se
        kb = KillerBee()
        slept = []
        monkeypatch.setattr(se.time, "sleep", lambda s: slept.append(s))
        p1, p2 = Dot15d4(b'\x01' * 10), Dot15d4(b'\x02' * 10)
        p1.time, p2.time = _t.time() + 100, _t.time() + 200
        n = se.__dict__["__kb_send"](kb, [p1, p2], verbose=0, count=1, realtime=1)
        assert n == 2
        assert any(x > 1 for x in slept)


class TestKbCryptoPaths:
    def test_decrypt_without_nwk(self, py_zigbee_crypt):
        pkt = ZigbeeSecurityHeader(data=b'\x00' * 8, mic=b'\x00' * 4)
        assert kbdecrypt(pkt, NWK_KEY) is None
        assert kbencrypt(pkt, b"x", NWK_KEY) is None

    def test_aps_payload_paths(self, py_zigbee_crypt):
        pkt = (Dot15d4(ENC_PKT)).copy()
        nwk = ZigbeeNWK(flags="security+extended_src", ext_src=0x0011223344556677, destination=1, source=2)
        sec = ZigbeeSecurityHeader(fc=1, source=0x0011223344556677, data=b'\x01\x02\x03\x04', mic=b'\x00' * 4)
        aps = ZigbeeAppDataPayload(delivery_mode=0, dst_endpoint=1, cluster=1, profile=0x0104, src_endpoint=1, counter=1)
        frame = nwk / sec / aps
        enc = kbencrypt(frame, b"\x00\x01\x02\x03", NWK_KEY)
        assert enc is not None
        dec = kbdecrypt(frame, NWK_KEY, doMicCheck=True)
        assert dec is not None
