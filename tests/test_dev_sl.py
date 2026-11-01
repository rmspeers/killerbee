"""Tests for the Silabs drivers (BeeHive and NodeTest) using a fake serial port."""

import pytest

from killerbee import dev_sl_beehive as bh
from killerbee import dev_sl_nodetest as nt
from killerbee.dev_sl_beehive import SL_BEEHIVE
from killerbee.dev_sl_nodetest import SL_NODETEST
from killerbee.kbutils import KBCapabilities


class FakeSerial:
    """Scripted pyserial-like port (bytes only). `reactions` maps exact written values to lines queued in response."""

    def __init__(self, **kw):
        self.kw = kw
        self.queue = []
        self.default = b">"
        self.reactions = {}
        self.written = []
        self.closed = False
        self.timeout = None

    def flush(self):
        pass

    def write(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("a bytes-like object is required, not '%s'" % type(data).__name__)
        self.written.append(data)
        for k, v in self.reactions.items():
            if data == k:
                self.queue.append(v)

    def readline(self):
        if self.queue:
            return self.queue.pop(0)
        return self.default

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def nosleep(monkeypatch):
    monkeypatch.setattr(bh.time, "sleep", lambda s: None)
    monkeypatch.setattr(nt.time, "sleep", lambda s: None)


def install(monkeypatch, mod, **kw):
    holder = {}

    def factory(**k):
        s = FakeSerial(**kw)
        holder["s"] = s
        return s

    monkeypatch.setattr(mod.serial, "Serial", factory)
    return holder


# ---------------------------------------------------------------- BeeHive
def mk_bh(monkeypatch, **kw):
    h = install(monkeypatch, bh, **kw)
    d = SL_BEEHIVE("/dev/ttyACM0")
    s = h["s"]
    s.reactions = {b"rx 1": b"Rx:Enabled", b"rx 0": b"Rx:Disabled"}
    return d, s


def test_bh_basic(monkeypatch):
    d, s = mk_bh(monkeypatch)
    assert d.get_dev_info() == ["/dev/ttyACM0", "BeeHive SG", ""]
    assert d.check_capability(KBCapabilities.INJECT)
    assert d.get_capabilities()
    with pytest.raises(Exception, match="Not yet"):
        d.ping(1, 2, 3)
    with pytest.raises(Exception, match="Not yet"):
        d.jammer_off()
    with pytest.raises(Exception):
        d.jammer_on()  # PHYJAM capability absent
    d.close()
    assert s.closed and d.handle is None


def test_bh_channel_and_cmd_failure(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.set_channel(15)
    assert b"setchannel 15" in s.written
    d.set_channel(15, 31)
    assert b"915MHz" in s.written and b"setchannel %d" % ((31 << 5 & 0xFF) + 15) in s.written
    d.set_channel(15, 28)
    assert b"863MHz" in s.written
    s.default = b""
    with pytest.raises(Exception, match="Could not send command"):
        d.set_channel(12)


def test_bh_sniffer_cycle(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on(channel=12)
    assert b"BeeHiveOptions 1 1 1 1" in s.written
    d.sniffer_on(channel=12, page=0)  # already open
    d.sniffer_off()
    # failure to start
    d2, s2 = mk_bh(monkeypatch)
    s2.reactions = {}
    with pytest.raises(Exception, match="Could not start"):
        d2.sniffer_on(channel=12)
    # failure to stop
    d3, s3 = mk_bh(monkeypatch)
    d3.sniffer_on(channel=12)
    s3.reactions = {}
    with pytest.raises(Exception, match="Could not stop"):
        d3.sniffer_off()


def test_bh_sniffer_on_no_channel(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on()
    assert not any(w.startswith(b"setchannel") for w in s.written)
    d.sniffer_off()
    d.inject(b"\x01", count=1)  # no channel given: must not touch channel either
    assert not any(w.startswith(b"setchannel") for w in s.written)


PKT = "{{(rxPacket)}{len:6}{timeUs:99}{crc:Pass}{rssi:-44}{lqi:210}{phy:0}{isAck:False}{syncWordId:0}{antenna:0}{payload: 0x05 0x01 0x02 0x03 0x04 0x05 }"


def test_bh_dissect_crc(monkeypatch):
    d, _ = mk_bh(monkeypatch)
    assert d._SL_BEEHIVE__dissect_pkt(PKT)[2] is True


def test_bh_dissect(monkeypatch):
    d, _ = mk_bh(monkeypatch)
    dis = d._SL_BEEHIVE__dissect_pkt
    rssi, out, crc = dis(PKT)
    assert out == b"\x01\x02\x03\x04\x05" and rssi == -44 and crc is True
    assert dis(PKT.replace("crc:Pass", "crc:Fail"))[2] is False
    assert dis("garbage") == (None, None, None)
    assert dis(PKT.replace(" 0x05 0x01", " 0x09 0x01")) == (None, None, None)  # bad length
    assert dis(PKT.replace("0x03", "0xZZ")) == (None, None, None)  # bad byte
    assert dis(PKT.replace("0x03", "0x103")) == (None, None, None)  # not a byte
    assert dis(PKT.replace("rssi:-44", "rssi:abc")) == (None, None, None)  # bad rssi
    assert dis(PKT.replace("{crc:Pass}", "")) == (None, None, None)  # missing field
    assert dis("{a:b:c:d:e:f:g:h:i:j:}") == (None, None, None)  # no payload
    assert dis("{payload: }") == (None, None, None)  # empty payload


def test_bh_pnext(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on(channel=12)
    s.default = b""
    assert d.pnext() is None  # timeout (empty line)
    s.queue = [PKT.encode()]
    r = d.pnext()
    assert r["rssi"] == -44 and r["bytes"] == b"\x01\x02\x03\x04\x05" and r["validcrc"] is True
    assert r[0] == r["bytes"] and r[1] is True and r[2] == -44
    assert r["location"] == (None, None, None)
    s.queue = [b"junk"]
    assert d.pnext() is None
    s.queue = [PKT.replace("rssi:-44", "rssi:bad").encode()]
    assert d.pnext() is None


def test_bh_inject(monkeypatch):
    d, s = mk_bh(monkeypatch)
    with pytest.raises(Exception, match="Empty"):
        d.inject(b"")
    with pytest.raises(Exception, match="too long"):
        d.inject(b"a" * 128)
    d.inject(b"\x01\x02\x03", channel=12, count=2)
    assert b"setTxLength 3" in s.written
    assert b"setTxPayload 00 03010203" in s.written
    assert s.written.count(b"tx 1") == 2
    # long packets are split in two payload writes
    s.written.clear()
    pkt = bytes(range(120))
    d.inject(pkt, channel=12)
    assert b"setTxLength 120" in s.written
    assert b"setTxPayload 00 78" + pkt[:118].hex().encode() in s.written
    assert b"setTxPayload 119 " + pkt[118:].hex().encode() in s.written


# ---------------------------------------------------------------- NodeTest
def mk_nt(monkeypatch):
    h = install(monkeypatch, nt)
    d = SL_NODETEST("/dev/ttyACM1")
    s = h["s"]
    s.reactions = {b"rx": b"{payload}", b"e": b"test end"}
    return d, s


def test_nt_basic(monkeypatch):
    d, s = mk_nt(monkeypatch)
    assert d.get_dev_info() == ["/dev/ttyACM1", "Silabs Node Test", ""]
    assert d.check_capability(KBCapabilities.SNIFF)
    assert d.get_capabilities()
    with pytest.raises(Exception, match="Not yet"):
        d.ping(1, 2, 3)
    with pytest.raises(Exception, match="Not yet"):
        d.jammer_off()
    with pytest.raises(Exception):
        d.jammer_on()
    with pytest.raises(Exception):
        d.inject(b"a")  # INJECT capability absent
    d.close()
    assert s.closed and d.handle is None


def test_nt_inject_after_cap(monkeypatch):
    d, s = mk_nt(monkeypatch)
    d.capabilities.setcapab(KBCapabilities.INJECT, True)
    with pytest.raises(Exception, match="Empty"):
        d.inject(b"")
    with pytest.raises(Exception, match="too long"):
        d.inject(b"a" * 126)
    with pytest.raises(Exception, match="Not yet"):
        d.inject(b"abc", channel=12)


def test_nt_channel(monkeypatch):
    d, s = mk_nt(monkeypatch)
    d.set_channel(15)
    assert b"setchannel 0f" in s.written
    d.set_channel(15, 28)
    assert b"setchannel 8f" in s.written
    s.default = b""
    with pytest.raises(Exception, match="Could not send command"):
        d.set_channel(12)


def test_nt_sniffer_cycle(monkeypatch):
    d, s = mk_nt(monkeypatch)
    d.sniffer_on(channel=12)
    d.sniffer_on(channel=12)
    d.sniffer_off()
    d2, s2 = mk_nt(monkeypatch)
    s2.reactions = {}
    with pytest.raises(Exception, match="Could not start"):
        d2.sniffer_on(channel=12)
    d3, s3 = mk_nt(monkeypatch)
    d3.sniffer_on(channel=12)
    s3.reactions = {}
    with pytest.raises(Exception, match="Could not stop"):
        d3.sniffer_off()


def nt_line(payload=(1, 2, 3), rssi="-40", length=None):
    n = "%02x" % (len(payload) if length is None else length)
    toks = " ".join(
        ["1", "0", "0", "0", "0", "200", rssi, "3", "5", "0", "100", "0", n]
        + ["0x%02x" % b for b in payload]
    )
    return ("{" + toks + "}").encode()


def test_nt_pnext(monkeypatch):
    d, s = mk_nt(monkeypatch)
    d.sniffer_on(channel=12)
    s.default = b""
    assert d.pnext() is None  # times out
    s.queue = [nt_line()]
    r = d.pnext()
    assert r["rssi"] == -40 and r["validcrc"] and r["bytes"][:3] == b"\x01\x02\x03"
    assert len(r["bytes"]) == 5
    for bad in (
        nt_line(length=7),
        nt_line(payload=(1,)).replace(b"0x01", b"0xzz"),
        nt_line(rssi="abc"),
    ):
        s.queue = [bad]
        assert d.pnext() is None


def test_jammer_on_with_cap(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.capabilities.setcapab(KBCapabilities.PHYJAM, True)
    with pytest.raises(Exception, match="Not yet"):
        d.jammer_on(channel=12)
    d, s = mk_nt(monkeypatch)
    d.capabilities.setcapab(KBCapabilities.PHYJAM, True)
    with pytest.raises(Exception, match="Not yet"):
        d.jammer_on(channel=12)


def test_nt_dissect_malformed(monkeypatch):
    d, _ = mk_nt(monkeypatch)
    dis = d._SL_NODETEST__dissect_pkt
    assert dis(b"{short}") is None  # too few fields
    assert dis(nt_line().replace(b"03 0x01", b"zz 0x01", 1)) is None  # bad length field
    assert dis(nt_line(payload=(1,)).replace(b"0x01", b"0x1ff")) is None  # not a byte
