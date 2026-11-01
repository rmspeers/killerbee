"""Tests for the Silabs drivers (BeeHive and NodeTest) using a fake serial port."""
import pytest

from killerbee import dev_sl_beehive as bh
from killerbee import dev_sl_nodetest as nt
from killerbee.dev_sl_beehive import SL_BEEHIVE
from killerbee.dev_sl_nodetest import SL_NODETEST
from killerbee.kbutils import KBCapabilities


class FakeSerial:
    """Scripted serial port. `reactions` maps exact written values to lines queued in response."""

    def __init__(self, text=True, strict=False, **kw):
        self.kw = kw
        self.text = text
        self.strict = strict
        self.queue = []
        self.default = ">" if text else b">"
        self.reactions = {}
        self.written = []
        self.closed = False
        self.timeout = None

    def flush(self):
        pass

    def write(self, data):
        if self.strict and isinstance(data, str):
            raise TypeError("a bytes-like object is required, not 'str'")
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
    s.reactions = {"rx 1": "Rx:Enabled", "rx 0": "Rx:Disabled"}
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
    assert "setchannel 15" in s.written
    d.set_channel(15, 31)
    assert "915MHz" in s.written and "setchannel %d" % ((31 << 5 & 0xFF) + 15) in s.written
    d.set_channel(15, 28)
    assert "863MHz" in s.written
    s.default = ""
    with pytest.raises(Exception, match="Could not send command"):
        d.set_channel(12)


def test_bh_sniffer_cycle(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on(channel=12)
    assert "BeeHiveOptions 1 1 1 1" in s.written
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


@pytest.mark.xfail(strict=False, reason="bug: sniffer_on() with no channel calls set_channel(None) -> '%d' % None TypeError")
def test_bh_sniffer_on_no_channel(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on()


@pytest.mark.xfail(strict=False, reason="py3 bug: SL_BEEHIVE writes str to pyserial (needs bytes)")
def test_bh_strict_serial_bytes(monkeypatch):
    d, s = mk_bh(monkeypatch, strict=True)
    d.set_channel(12)


PKT = "{{(rxPacket)}{len:6}{timeUs:99}{crc:Pass}{rssi:-44}{lqi:210}{phy:0}{isAck:False}{syncWordId:0}{antenna:0}{payload: 0x05 0x01 0x02 0x03 0x04 0x05 }"


@pytest.mark.xfail(strict=False, reason="bug: __dissect_pkt reads crc from the rssi field (index 4) so validcrc is always False")
def test_bh_dissect_crc(monkeypatch):
    d, _ = mk_bh(monkeypatch)
    assert d._SL_BEEHIVE__dissect_pkt(PKT)[2] is True


def test_bh_dissect(monkeypatch):
    d, _ = mk_bh(monkeypatch)
    dis = d._SL_BEEHIVE__dissect_pkt
    rssi, out, crc = dis(PKT)
    assert out == "\x01\x02\x03\x04\x05" and rssi == "-44"
    assert dis("garbage") == (None, None, None)
    assert dis(PKT.replace(" 0x05 0x01", " 0x09 0x01")) == (None, None, None)  # bad length
    assert dis(PKT.replace("0x03", "0xZZ")) == (None, None, None)  # bad byte
    assert dis("{a:b:c:d:e:f:g:h:i:j:}") == (None, None, None)  # empty payload


def test_bh_pnext(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on(channel=12)
    s.default = ""
    assert d.pnext() is None  # timeout (empty line)
    monkeypatch.setattr(SL_BEEHIVE, "_SL_BEEHIVE__dissect_pkt", lambda self, p: ("-44", "abc", True))
    s.queue = ["pkt"]
    r = d.pnext()
    assert r["rssi"] == -44 and r["bytes"] == "abc" and r["validcrc"] and r["location"] == (None, None, None)
    monkeypatch.setattr(SL_BEEHIVE, "_SL_BEEHIVE__dissect_pkt", lambda self, p: ("bad", "abc", True))
    s.queue = ["pkt"]
    assert d.pnext() is None
    monkeypatch.setattr(SL_BEEHIVE, "_SL_BEEHIVE__dissect_pkt", lambda self, p: (None, None, None))
    s.queue = ["pkt"]
    assert d.pnext() is None


@pytest.mark.xfail(strict=False, reason="bug: crc parsed from rssi field, so validcrc is always False")
def test_bh_pnext_real_packet(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.sniffer_on(channel=12)
    s.default = ""
    s.queue = [PKT]
    assert d.pnext()["validcrc"] is True


class HexStr(str):
    """str whose .encode('hex') works, emulating py2 semantics the driver expects."""
    def encode(self, enc="utf-8"):
        return "ab" * len(self)

    def __getitem__(self, i):
        return HexStr(str.__getitem__(self, i))


def test_bh_inject(monkeypatch):
    d, s = mk_bh(monkeypatch)
    with pytest.raises(Exception, match="Empty"):
        d.inject(b"")
    with pytest.raises(Exception, match="too long"):
        d.inject(b"a" * 128)
    d.inject(HexStr("x" * 3), channel=12, count=2)
    d.inject(HexStr("x" * 120), channel=12)
    assert "setTxLength 120" in s.written


@pytest.mark.xfail(strict=False, reason="py3 bug: inject() uses packet.encode('hex'), unavailable for bytes/str in py3")
def test_bh_inject_bytes(monkeypatch):
    d, s = mk_bh(monkeypatch)
    d.inject(b"\x01\x02\x03", channel=12)


# ---------------------------------------------------------------- NodeTest
def mk_nt(monkeypatch):
    h = install(monkeypatch, nt, text=False)
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
    with pytest.raises(TypeError):  # str join with bytes: py3 bug before NotImplemented
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
    toks = " ".join(["1", "0", "0", "0", "0", "200", rssi, "3", "5", "0", "100", "0", n] +
                    ["0x%02x" % b for b in payload])
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
    for bad in (nt_line(length=7), nt_line(payload=(1,)).replace(b"0x01", b"0xzz"),
                nt_line(rssi="abc")):
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
