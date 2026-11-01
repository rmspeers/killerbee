import struct
import types
from socket import timeout as sock_timeout

import pytest

from killerbee import dev_sewio as sw
from killerbee.dev_sewio import SEWIO
from killerbee.kbutils import KBCapabilities, KBInterfaceError

IP = "10.10.10.2"


class Resp:
    def __init__(self, data, status=200):
        self.data = data.encode() if isinstance(data, str) else data
        self.status = status


class Sniffer:
    """Tiny model of the Sewio web interface."""

    def __init__(self, fw="0.9.0", running=False, chan=11):
        self.fw = fw
        self.running = running
        self.chan = chan
        self.urls = []
        self.toggle_works = True
        self.status_code = 200
        self.fail = False
        self.broken_page = False
        self.empty_status = False

    def page(self):
        if self.broken_page:
            return "nothing here"
        return (
            "Firmware version %s <!--#pindex-->%s,00:1a:b6:00:0a:a4,10.10.10.2,%d,High,0x0000,OFF,0,0"
            % (self.fw, "RUNNING" if self.running else "STOPPED", self.chan)
        )

    def request(self, method, url):
        if self.fail:
            raise OSError("down")
        self.urls.append(url)
        path = url.split("/", 3)[3]
        if path == "":
            return Resp(self.page())
        if path.startswith("status.cgi?p=4") and self.empty_status:
            return Resp("")
        if path.startswith("status.cgi?p=2") and self.toggle_works:
            self.running = not self.running
        if path.startswith("settings.cgi"):
            self.chan = int(path.split("chn=")[1].split("&")[0])
        return Resp("ok", self.status_code)


class FakeSock:
    bind_fail = False

    def __init__(self, *a):
        self.queue = []
        self.closed = False
        self.bound = None

    def setsockopt(self, *a):
        pass

    def bind(self, addr):
        if self.bind_fail:
            raise OSError("in use")
        self.bound = addr

    def settimeout(self, t):
        self.t = t

    def recvfrom(self, n):
        if not self.queue:
            raise sock_timeout()
        return self.queue.pop(0)

    def close(self):
        self.closed = True


@pytest.fixture
def env(monkeypatch):
    s = Sniffer()
    monkeypatch.setattr(sw, "urllib3", types.SimpleNamespace(request=s.request))
    monkeypatch.setattr(sw, "socket", FakeSock)
    return s


def mk(env, **kw):
    return SEWIO(IP, **kw)


def test_module_helpers(env, monkeypatch, capsys):
    assert sw.getFirmwareVersion(IP) == "0.9.0"
    assert sw.getMacAddr(IP) == "00:1a:b6:00:0a:a4"
    assert sw.isSewio(IP)
    assert not sw.isSewio("notanip")
    # new-style UI parsing
    env.page = lambda: "x,10.10.10.2,foo,0.9.1x)"
    assert sw.getFirmwareVersion(IP) == "0.9.1"
    env.page = lambda: "10.10.10.2 )"
    assert sw.getFirmwareVersion(IP) is None  # ValueError swallowed
    env.page = lambda: "nothing"
    assert sw.getMacAddr(IP) is None
    env.fail = True
    assert sw.getFirmwareVersion(IP) is None
    assert sw.getMacAddr(IP) is None
    out = sw.ntp_to_system_time(2208988800 + 5, 0)
    assert out.year == 1970


def test_init_and_info(env):
    d = mk(env)
    assert d.handle.bound == ("10.10.10.1", 17754)
    assert d.check_capability(KBCapabilities.INJECT)
    assert d.get_capabilities()
    assert d.get_dev_info() == [IP, "Sewio Open-Sniffer v0.9.0", "00:1a:b6:00:0a:a4"]
    h = d.handle
    d.close()
    assert h.closed and d.handle is None


def test_init_old_fw_and_bind_fail(env, monkeypatch, capsys):
    env.fw = "0.5"
    orig = FakeSock.bind
    monkeypatch.setattr(FakeSock, "bind_fail", True, raising=False)
    d = mk(env)
    assert not d.check_capability(KBCapabilities.INJECT)
    out = capsys.readouterr().out
    assert "Attempted to bind" in out
    env.fw = "9.9"
    d = mk(env)
    assert "not currently supported" in capsys.readouterr().out


def test_sniffer_on_off(env):
    d = mk(env)
    d.sniffer_on(channel=15)
    assert env.running and env.chan == 15 and d._channel == 15
    d.sniffer_on()  # already on: no-op
    d.sniffer_off()
    assert not env.running
    d.sniffer_off()  # already off
    d.set_channel(15)  # same channel branch
    with pytest.raises(Exception, match="Invalid channel"):
        d.set_channel(99)


def test_sniffer_errors(env):
    d = mk(env)
    env.status_code = 500
    with pytest.raises(KBInterfaceError, match="start capture"):
        d.sniffer_on()
    env.status_code = 200
    env.running = False
    env.toggle_works = False
    with pytest.raises(KBInterfaceError, match="did not turn on"):
        d.sniffer_on()
    env.running = True
    env.status_code = 500
    with pytest.raises(KBInterfaceError, match="stop capture"):
        d.sniffer_off()
    env.status_code = 200
    env.running = True
    with pytest.raises(KBInterfaceError, match="did not turn off"):
        d.sniffer_off()
    env.broken_page = True
    with pytest.raises(KBInterfaceError, match="current status"):
        d.sniffer_on()
    with pytest.raises(KBInterfaceError, match="current channel"):
        d.set_channel(12)
    env.fail = True
    env.broken_page = False
    with pytest.raises(KBInterfaceError, match="Unable to preform"):
        d.sniffer_on()


def test_inject_and_jam(env):
    d = mk(env)
    d.inject(b"\x01\x02", channel=12, count=3, delay=1)
    assert any(u.startswith("http://10.10.10.2/inject.cgi?chn=12") for u in env.urls)
    with pytest.raises(ValueError):
        d.inject(b"")
    with pytest.raises(ValueError):
        d.inject(b"a" * 126)
    d.jammer_on(channel=13, method="2")
    d.jammer_on()
    with pytest.raises(ValueError):
        d.jammer_on(method="9")
    env.status_code = 500
    with pytest.raises(KBInterfaceError, match="start jamming"):
        d.jammer_on()
    assert hasattr(d.jammer_off, "__func__")
    env.status_code = 200
    d.jammer_off()


def test_jammer_off_fail(env):
    d = mk(env)
    env.empty_status = True
    with pytest.raises(KBInterfaceError, match="stop jamming"):
        d.jammer_off()


def test_caps_required_old_fw(env):
    env.fw = "0.5"
    d = mk(env)
    with pytest.raises(Exception):
        d.inject(b"a")
    with pytest.raises(Exception):
        d.jammer_on()


def zep_data(crcmode=1, payload=b"\x61\x62\x63", ch=15, ver=2):
    hdr = struct.pack("<HBB", 22597, ver, 1)
    body = struct.pack(">BHBBIII10xB", ch, 1, crcmode, 77, 0, 0, 1, len(payload))
    return hdr + body + payload


def test_parse_zep_variants():
    parse = SEWIO._SEWIO__parse_zep_v2
    frame, ch, valid, rssi, lqi, _ = parse(zep_data(crcmode=1))
    assert frame == b"abc" and ch == 15 and valid is False and rssi is None and lqi == 77
    with pytest.raises(Exception, match="preamble"):
        parse(b"\x00" * 40)
    ack = struct.pack("<HBB", 22597, 2, 2) + struct.pack(">I", 5) + b"\x01\x02\x03\x04"
    f, ch, valid, rssi, lqi, _ = parse(ack)
    assert f == b"\x01\x02\x03\x04" and ch is None and valid is False
    assert parse(struct.pack("<HBB", 22597, 2, 9) + b"\x00" * 30) is None


def test_parse_zep_crcmode0():
    parse = SEWIO._SEWIO__parse_zep_v2
    frame, ch, valid, rssi, lqi, _ = parse(zep_data(crcmode=0, payload=b"abc\xb1\x85"))
    assert valid is True and rssi == 0xB1


def test_pnext(env, monkeypatch):
    d = mk(env)
    sock = d.handle
    sock.queue = [(b"junk", ("1.2.3.4", 1)), (zep_data(), (IP, 17754))]
    r = d.pnext()
    assert r["bytes"] == b"abc" and r["dbm"] is None and r["validcrc"] is False
    assert env.running
    assert d.pnext() is None  # timeout


def test_pnext_unknown_zep_type(env):
    d = mk(env)
    d.sniffer_on()
    bad = struct.pack("<HBB", 22597, 2, 9) + b"\x00" * 30
    d.handle.queue = [(bad, (IP, 1))]
    assert d.pnext() is None


@pytest.mark.parametrize("rssi,dbm", [(0xB1, -79), (10, 10)])
def test_pnext_dbm(env, monkeypatch, rssi, dbm):
    d = mk(env)
    d.sniffer_on()
    monkeypatch.setattr(
        SEWIO, "_SEWIO__parse_zep_v2", staticmethod(lambda data: (b"f", 11, True, rssi, 1, None))
    )
    d.handle.queue = [(b"x", (IP, 1))]
    assert d.pnext()["dbm"] == dbm


@pytest.mark.parametrize(
    "chan,mod",
    [(11, "0"), (26, "0"), (1, "c"), (10, "c"), (128, "1c"), (131, "1c"), (0, "0"), (50, None)],
)
def test_default_modulation(chan, mod):
    assert SEWIO._SEWIO__get_default_modulation(chan) == mod
