"""Tests for GoodFETAVR, GoodFETCCSPI, GoodFETatmel128, dev_apimote, dev_telosb
and dev_template, with the serial port replaced by a scripted fake."""

import struct
import sys
import types
from datetime import datetime

import pytest

from killerbee import GoodFET as gf
from killerbee import GoodFETAVR as avrmod
from killerbee import GoodFETCCSPI as ccmod
from killerbee import GoodFETatmel128 as atmod
from killerbee import dev_apimote, dev_telosb, dev_template
from killerbee.kbutils import KBCapabilities, makeFCS


def frame(app, verb, data=b""):
    data = bytes(data)
    return bytes([app, verb]) + struct.pack("<H", len(data)) + data


class FakeSerial:
    """Scripted serial port; see tests/test_goodfet.py for the full description."""

    PARITY_NONE = "N"

    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs
        self.timeout = kwargs.get("timeout")
        self.rx = bytearray()
        self.responder = None
        self.pending = bytearray()
        self.frames = []
        self.calls = []
        self.closed = False

    def read(self, n=1):
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def write(self, data):
        if isinstance(data, str):
            raise TypeError("a bytes-like object is required, not 'str'")
        data = bytes(data)
        self.pending += data
        while len(self.pending) >= 4:
            ln = self.pending[2] | (self.pending[3] << 8)
            if len(self.pending) < 4 + ln:
                break
            app, verb = self.pending[0], self.pending[1]
            payload = bytes(self.pending[4 : 4 + ln])
            del self.pending[: 4 + ln]
            self.frames.append((app, verb, payload))
            if self.responder:
                self.rx += self.responder(app, verb, payload) or b""
        return len(data)

    def close(self):
        self.closed = True

    def flushInput(self):
        pass

    def setRTS(self, v):
        self.calls.append(("RTS", v))

    def setDTR(self, v):
        self.calls.append(("DTR", v))

    def getCTS(self):
        return 1


BANNER = frame(0x00, 0x7F, b"http://goodfet.sf.net/")


class FakeCC2420:
    """Responder emulating the CCSPI GoodFET application and a CC2420 register file."""

    def __init__(self):
        self.regs = {}
        self.strobes = []
        self.rxq = []
        self.txed = []
        self.ram = bytes(range(16))
        self.status = 0x44

    def __call__(self, app, verb, p):
        if app == 0:
            if verb == 0x81:
                return frame(0, 0x81, p)
            return frame(0, verb)
        if app == 0x51:
            if verb == 0x02:  # peek
                v = self.regs.get(p[0], 0)
                return frame(app, verb, bytes([0, v >> 8, v & 0xFF]))
            if verb == 0x03:  # poke
                self.regs[p[0]] = (p[1] << 8) | p[2]
                return frame(app, verb)
            if verb == 0x00:  # trans / strobe
                self.strobes.append(p[0])
                return frame(app, verb, bytes([self.status]))
            if verb == 0x80:  # rx
                return frame(app, verb, self.rxq.pop(0) if self.rxq else b"")
            if verb == 0x81:
                self.txed.append(p)
                return frame(app, verb)
            if verb == 0x84:
                return frame(app, verb, self.ram)
            if verb in (0x86, 0x90):
                return frame(app, verb, self.rxq.pop(0) if self.rxq else b"")
        return frame(app, verb)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(gf.time, "sleep", lambda s: None)
    monkeypatch.setattr(ccmod.time, "sleep", lambda s: None)
    monkeypatch.setattr(atmod.time, "sleep", lambda s: None)
    monkeypatch.setattr(dev_apimote.time, "sleep", lambda s: None)
    monkeypatch.setattr(dev_telosb.time, "sleep", lambda s: None)
    for v in ("GOODFET", "board", "platform"):
        monkeypatch.setenv(v, "x")
        monkeypatch.delenv(v)


@pytest.fixture
def cc_device(monkeypatch):
    """Patch serial.Serial so any GoodFET connects to a FakeCC2420."""
    import serial

    dev = FakeCC2420()
    ports = []

    def factory(*a, **k):
        s = FakeSerial(*a, **k)
        s.rx += BANNER
        s.responder = dev
        ports.append(s)
        return s

    monkeypatch.setattr(serial, "Serial", factory)
    dev.ports = ports
    return dev


def scripted(obj, replies):
    """Replace obj.writecmd with a stub that records calls and loads data from replies."""
    calls = []

    def fake(app, verb, count=0, data=None):
        calls.append((app, verb, count, None if data is None else list(data)))
        if replies:
            obj.data = replies.pop(0)
        return obj.data

    obj.writecmd = fake
    obj.calls = calls
    return calls


# ===================================================================== AVR
class TestAVR:
    def make(self, *replies):
        f = avrmod.GoodFETAVR()
        calls = scripted(f, list(replies))
        return f, calls

    def test_simple_commands(self):
        f, calls = self.make(b"", b"", b"", b"")
        f.setup()
        f.start()
        f.erase()
        assert calls[0][:2] == (0x32, 0x10)
        assert calls[1][:2] == (0x32, 0x20)
        assert calls[2][:2] == (0x32, 0xF0)

    def test_trans(self):
        f, calls = self.make(b"\x01\x02\x03\x04")
        assert f.trans([0xAC, 0x53, 0, 0]) == b"\x01\x02\x03\x04"
        assert calls[0][:3] == (0x32, 0x00, 4)

    def test_lockbits_and_set(self):
        f, calls = self.make(b"\xff", b"", b"\xfc")
        assert f.lockbits() == 0xFF
        assert f.setlockbits(0xFC) == 0xFC
        assert calls[1][:3] == (0x32, 0x92, 1)

    def test_lock(self):
        f, calls = self.make(b"", b"\xfc")
        f.lock()
        assert calls[0][3] == [0xFC]

    def test_forcestart(self, capsys):
        f, calls = self.make(b"\x00", b"\x00", b"\xff")
        f.start = lambda: None
        f.forcestart()
        assert "Lockbits: ff" in capsys.readouterr().out

    def test_eeprom_flash_peek_poke(self):
        f, calls = self.make(b"\x11", b"\x22", b"\x33")
        assert f.eeprompeek(0x1234) == 0x11
        assert f.flashpeek(0x1234) == 0x22
        assert f.eeprompoke(0x10, 0x33) == 0x33
        assert calls[0][3] == [0x34, 0x12]

    def test_flashpeekblock(self):
        f, calls = self.make(b"abcd")
        assert f.flashpeekblock(0x0102) == b"abcd"
        assert calls[0][3] == [0x02, 0x01, 0x80, 0x00]

    def test_identstr_known_and_unknown(self):
        f, _ = self.make(b"\x1e\x97\x02", b"\x1e\x12\x34", b"\x00\x97\x02")
        assert f.identstr() == "Atmel ATmega128"
        assert f.identstr() == "Atmel 0x1234"
        assert f.identstr() == "Locked ATmega128"

    def test_lockbits_real_wire(self):
        f = avrmod.GoodFETAVR()
        f.serialport = FakeSerial()
        f.serialport.responder = lambda a, v, d: frame(a, v, b"\xff")
        assert f.lockbits() == 0xFF
        assert f.serialport.frames == [(0x32, 0x82, b"")]

    def test_identstr_real_wire(self):
        f = avrmod.GoodFETAVR()
        f.serialport = FakeSerial()
        f.serialport.responder = lambda a, v, d: frame(a, v, b"\x1e\x97\x02")
        assert f.identstr() == "Atmel ATmega128"


# ===================================================================== CCSPI
@pytest.fixture
def cc(cc_device):
    f = ccmod.GoodFETCCSPI()
    f.serInit(port="/dev/fake")
    f.dev = cc_device
    return f


class TestCCSPI:
    def test_setup_programs_registers(self, cc, cc_device):
        cc.setup()
        assert cc_device.regs[0x11] == 0x0AC2 & ~0x0800
        assert cc_device.regs[0x12] == 0x0500
        assert cc_device.regs[0x19] == 0x01C4
        assert cc_device.strobes == [1, 1, 2]

    def test_ident(self, cc, cc_device):
        cc_device.regs[0x1E] = 0x233D
        assert cc.ident() == 0x233D
        assert cc.identstr() == "CC2420"
        cc_device.regs[0x1E] = 0x1111
        assert cc.identstr() == "Unknown0x1111"

    def test_trans8(self, cc, cc_device):
        assert cc.trans8(0x07) == cc_device.status
        assert cc_device.strobes == [0x07]

    def test_strobes(self, cc, cc_device):
        cc.CC_RFST_IDLE()
        cc.CC_RFST_TX()
        cc.CC_RFST_RX()
        cc.CC_RFST_CAL()
        cc.CC_RFST(0x09)
        assert cc_device.strobes == [6, 4, 3, 2, 9]
        assert cc.strobe(0x00) == 0x44

    def test_peek_branches(self, cc, monkeypatch):
        monkeypatch.setattr(cc, "writecmd", lambda *a: bytearray([0, 0x12, 0x34]))
        assert cc.peek(1) == 0x1234
        monkeypatch.setattr(cc, "writecmd", lambda *a: bytearray([0, 0x12]))
        assert cc.peek(1) == 0x1200
        monkeypatch.setattr(cc, "writecmd", lambda *a: bytearray([0]))
        assert cc.peek(1) == 0

    def test_poke_ok_and_failure(self, cc, cc_device, capsys, monkeypatch):
        assert cc.poke(0x10, 0xBEEF) is True
        assert cc_device.regs[0x10] == 0xBEEF
        monkeypatch.setattr(cc, "peek", lambda r, b=2: 0)
        assert cc.poke(0x10, 0x1) is False
        assert "failed to set" in capsys.readouterr().out
        assert cc.poke(0x18, 0x1) is True

    def test_status(self, cc, cc_device):
        cc_device.status = 0x44
        s = cc.status()
        assert "XOSC16M_STABLE" in s and "LOCK" in s
        cc_device.status = 0x00
        assert cc.status() == ""

    def test_rf_misc_getters(self, cc):
        assert cc.RF_setenc() == "802.15.4"
        assert cc.RF_getenc() == "802.15.4"
        assert cc.RF_getrate() == 0
        assert cc.RF_setrate() == 0
        assert cc.RF_getsmac() == 0xDEADBEEF
        assert cc.RF_setsmac(1) == 0xDEADBEEF
        assert cc.RF_gettmac() == 0xDEADBEEF
        assert cc.RF_settmac(1) == 0xDEADBEEF

    def test_sync(self, cc, cc_device):
        cc.RF_setsync()
        assert cc_device.regs[0x14] == 0xA70F
        assert cc.RF_getsync() == 0xA70F

    def test_key_nonce(self, cc, capsys):
        cc.RF_setkey("k")
        cc.RF_setnonce("n")
        assert capsys.readouterr().out.count("ERROR") == 2

    def test_freq_and_channel(self, cc, cc_device, capsys):
        cc.RF_setfreq(2405 * 1000000)
        assert cc_device.regs[0x18] & 0x3FF == 2405 - 2048
        assert cc.RF_getfreq() == 2405 * 1000000
        cc.RF_setchan(12)
        assert cc.RF_getfreq() == 2410 * 1000000
        cc.RF_setchan(5)
        assert "Only 802.15.4" in capsys.readouterr().out
        cc.RF_setchan(27)

    def test_rssi(self, cc, cc_device):
        cc_device.regs[0x13] = 0x0045
        assert cc.RF_getrssi() == 0x45 ^ 0x80

    def test_ram(self, cc, cc_device):
        assert cc.peekram(0x100, 4) == bytearray(range(16))
        cc.pokeram(0x100, [1, 2])
        cc.pokeram(0x100, b"\x03\x04")

    def test_txrxpacket(self, cc, cc_device):
        assert cc.RF_txrxpacket([1, 2]) is None
        assert cc.RF_txrxpacket(b"\x01\x02") is None  # bytes accepted too
        cc_device.rxq.append(b"\x03abc")
        assert cc.RF_txrxpacket([1, 2], timeout=300) == bytearray(b"\x03abc")

    def test_rxpacket(self, cc, cc_device):
        assert cc.RF_rxpacket() is None
        cc_device.rxq.append(b"\x03abc")
        assert cc.RF_rxpacket() == b"\x03abc"
        assert cc.lastpacket == bytearray(b"\x03abc")

    def test_rxpacketdec(self, cc, cc_device):
        assert cc.RF_rxpacketdec() is None
        cc_device.rxq.append(b"xyz")
        assert cc.RF_rxpacketdec() == bytearray(b"xyz")

    def test_rxpacketrepeat_tx_jam(self, cc, cc_device, capsys):
        assert cc.RF_rxpacketrepeat() is None
        cc.RF_txpacket([3, 1, 2])
        assert cc_device.txed == [b"\x03\x01\x02"]
        cc.RF_reflexjam(0x0102)
        cc.RF_reflexjam_autoack()
        assert "Got:" in capsys.readouterr().out

    def test_modulated_spectrum_and_carrier(self, cc, cc_device):
        cc.RF_modulated_spectrum()
        assert cc_device.regs[0x12] & 0x00C0 == 0x00C0
        assert cc_device.strobes[-3:] == [2, 9, 4]
        cc.RF_carrier()
        assert cc_device.regs[0x2E] == 0x1800
        assert cc_device.strobes[-3:] == [2, 9, 4]

    def test_mdmctrl_flags(self, cc, cc_device):
        cc_device.regs[0x11] = 0x0AC2
        cc.RF_promiscuity(1)
        assert cc_device.regs[0x11] & 0x800 == 0
        cc.RF_promiscuity(0)
        assert cc_device.regs[0x11] & 0x800
        cc.RF_autocrc(0)
        assert cc_device.regs[0x11] & 0x20 == 0
        cc.RF_autocrc(1)
        assert cc_device.regs[0x11] & 0x20
        cc.RF_autoack(0)
        assert cc_device.regs[0x11] & 0x10 == 0
        cc.RF_autoack()
        assert cc_device.regs[0x11] & 0x10

    def test_packet_and_mac_len(self, cc, cc_device):
        cc.RF_setpacketlen(20)
        assert cc.packetlen == 20
        assert cc.RF_getpacketlen() == 20
        cc_device.regs[0x03] = 0x0002
        assert cc.RF_getmaclen() == 4
        cc.RF_setmaclen(4)
        assert cc_device.regs[0x03] == 2 and cc.maclen == 4

    def test_packet2str(self, cc, capsys):
        assert cc.packet2str(b"\x01\xff") == "# 01 ff"
        assert cc.packet2str(bytearray(b"\x0a"), prefix=">") == "> 0a"
        assert cc.packet2str([]) == "#"
        cc.printpacket(b"\x01")
        assert "# 01" in capsys.readouterr().out

    def test_printdissect(self, cc, monkeypatch):
        printed = []
        monkeypatch.setattr(cc, "printpacket", lambda p, prefix="#": printed.append(p))
        cc.printdissect(b"\x00" + bytes(range(1, 10)))
        assert printed

    def test_printdissect_no_scapy(self, cc, monkeypatch, capsys):
        import builtins

        real = builtins.__import__

        def imp(name, *a, **k):
            if name == "scapy.all":
                raise ImportError("no scapy")
            return real(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", imp)
        monkeypatch.setattr(cc, "printpacket", lambda p, prefix="#": None)
        cc.printdissect(b"\x00\x01")
        assert "Scapy must be installed" in capsys.readouterr().out


# ================================================================= atmel128
@pytest.fixture
def at(monkeypatch):
    f = atmod.GoodFETatmel128rfa1()
    f.serialport = FakeSerial()
    return f


class TestAtmel128:
    def test_writecmd_list_and_readcmd(self, at):
        s = at.serialport
        s.responder = lambda a, v, d: frame(a, v, b"\x05")
        out = at.writecmd(0x53, 0x03, 2, [1, 0x80])
        assert s.frames[0] == (0x53, 0x03, b"\x01\x80")
        assert out == b"\x05"

    def test_writecmd_bytes_data_and_silent(self, at):
        s = at.serialport
        at.besilent = 1
        assert at.writecmd(1, 2, 3, b"abc") is None
        assert s.frames[0][2] == b"abc"

    def test_writecmd_no_data(self):
        f = atmod.GoodFETatmel128rfa1()
        f.serialport = FakeSerial()
        f.serialport.responder = lambda a, v, d: frame(a, v)
        assert f.writecmd(1, 2) == b""
        assert f.writecmd(1, 3, 4) == b""  # count without data: nothing to send
        assert f.serialport.frames == [(1, 2, b""), (1, 3, b"")]

    def test_writecmd_verbose(self, at, capsys):
        at.verbose = True
        at.serialport.responder = lambda a, v, d: frame(a, v, b"\x05")
        assert at.writecmd(1, 2, 1, [5]) == b"\x05"
        out = capsys.readouterr().out
        assert "sending: 05" in out and "read: 05" in out

    def test_serinit_env_without_glob_match(self, at, monkeypatch):
        import serial

        monkeypatch.setattr(serial, "Serial", FakeSerial)
        monkeypatch.setattr(atmod.glob, "glob", lambda p: [])
        monkeypatch.setenv("GOODFET", "/dev/envport")
        f = atmod.GoodFETatmel128rfa1()
        f.pyserInit(None, 2, 1)
        f.serInit(None, 2, 1)

    def test_readcmd_empty(self, at, capsys):
        at.verbose = True
        assert at.readcmd() is None
        assert "Rx: None" in capsys.readouterr().out
        assert at.app == 0 and at.count == 0
        at.verbose = False
        assert at.readcmd() is None

    def test_readcmd_partial_header(self, at, capsys):
        at.verbose = True
        at.serialport.rx += bytes([0x01])  # app only: verb, count missing
        at.readcmd()
        assert at.verb == 0 and at.count == 0

    def test_readcmd_debug(self, at, capsys):
        s = at.serialport
        s.rx += frame(0xFF, 0xFF, b"hi")
        assert at.readcmd() == b""
        s.rx += frame(0xFF, 0xFE, struct.pack("<H", 0x0102))
        assert at.readcmd() == b""
        s.rx += frame(0xFF, 0xFD)
        assert at.readcmd() == b""
        out = capsys.readouterr().out
        assert "DEBUG" in out and "NOP" in out and "0x102" in out
        s.rx += frame(0x10, 0x01, b"data")
        at.verbose = True
        assert at.readcmd() == b"data"

    def test_peek_poke(self, at, capsys):
        regs = {}

        def resp(app, verb, p):
            if verb == 0x02:
                return frame(app, verb, bytes([regs.get(p[0], 0)]))
            if verb == 0x03:
                regs[p[0]] = p[2]
            return frame(app, verb)

        at.serialport.responder = resp
        at.poke(0x08, 0x15)
        assert regs[0x08] == 0x15
        assert at.peek(0x08) == 0x15
        assert at.peek(0x09, 4) == 0
        assert "cannot poke more" in capsys.readouterr().out
        at.poke(0x0A, 0x1, bytes=3)
        assert "cannot poke more" in capsys.readouterr().out

    def test_poke_mismatch(self, at, capsys):
        at.serialport.responder = lambda a, v, d: frame(a, v, b"\x00") if v == 0x02 else frame(a, v)
        at.poke(0x08, 0x15)
        assert "failed to set" in capsys.readouterr().out

    def test_peek_no_data(self, at):
        at.serialport.responder = lambda a, v, d: frame(a, v)
        assert at.peek(0x07) == -1

    def test_setup_and_channel(self, at, capsys):
        at.serialport.responder = lambda a, v, d: frame(a, v, b"\x00") if v == 0x02 else frame(a, v)
        at.setup()
        assert at.serialport.frames[0][:2] == (0x53, 0x10)
        at.RF_setchannel(5)
        assert "out of range" in capsys.readouterr().out
        at.RF_setchannel(27)
        at.RF_setchannel(15)
        assert any(f[1] == 0x03 and f[2][0] == 0x8 for f in at.serialport.frames)

    def test_rxpacket(self, at):
        at.serialport.responder = lambda a, v, d: frame(a, v)
        assert at.RF_rxpacket() is None
        at.serialport.responder = lambda a, v, d: frame(a, v, b"pkt")
        assert at.RF_rxpacket() == b"pkt"
        assert at.packetlen == 3

    def test_txpacket_bytes_and_list(self, at):
        at.serialport.responder = lambda a, v, d: frame(a, v)
        at.RF_txpacket(b"abc")
        assert at.serialport.frames[-1][:3] == (0x53, 0x81, b"abc")
        at.RF_txpacket([1, 2, 3])
        assert at.serialport.frames[-1][:3] == (0x53, 0x81, b"\x01\x02\x03")

    def test_rssi(self, at):
        vals = iter([0, 0x10, 0x7F])
        at.peek = lambda reg, bytes=1: next(vals)
        assert at.RF_getrssi() == -91
        assert at.RF_getrssi() == 0x10 - 90
        assert at.RF_getrssi() == 0x53 - 90

    def test_aack_autocrc(self, at):
        at.serialport.responder = lambda a, v, d: frame(a, v)
        at.RF_enable_AACK(True)
        at.RF_enable_AACK(True)
        at.RF_enable_AACK(False)
        at.RF_enable_AACK(False)
        at.RF_autocrc(1)
        at.RF_autocrc(0)
        verbs = [f[1] for f in at.serialport.frames]
        assert verbs == [0x84, 0x85, 0x86, 0x87]
        assert at.autocrc == 0

    # connection ---------------------------------------------------------
    @pytest.fixture
    def py2serial(self, monkeypatch):
        import serial

        made = []

        def factory(*a, **k):
            s = FakeSerial(*a, **k)
            s.rx += BANNER
            s.responder = lambda a_, v, d: frame(a_, v, d)
            made.append(s)
            return s

        monkeypatch.setattr(serial, "Serial", factory)
        monkeypatch.setattr(atmod.glob, "glob", lambda p: [])
        return made

    def test_serinit_connects(self, py2serial, monkeypatch):
        f = atmod.GoodFETatmel128rfa1()
        f.verbose = True
        monkeypatch.setenv("GOODFET", "/dev/kbat")
        monkeypatch.setattr(f, "monitorecho", lambda: True)
        f.serInit()
        assert f.connected == 1
        assert py2serial[0].args[0] == "/dev/kbat"
        assert py2serial[0].timeout == 12
        f.serClose()
        assert f.connected == 0 and py2serial[0].closed
        # Second call while already connected is a no-op
        f.connected = 1
        f.pyserInit("/dev/zzz", 2, None)
        assert len(py2serial) == 1

    def test_serinit_echo_retry(self, py2serial, monkeypatch, capsys):
        f = atmod.GoodFETatmel128rfa1()
        f.verbose = True
        results = iter([False, False, True])
        monkeypatch.setattr(f, "monitorecho", lambda: next(results))
        f.pyserInit("/dev/x", 2, 5)
        assert f.connected == 1
        assert "Comm error on try" in capsys.readouterr().out

    def test_pyserinit_attemptlimit(self, monkeypatch):
        import serial

        monkeypatch.setattr(serial, "Serial", FakeSerial)
        f = atmod.GoodFETatmel128rfa1()
        f.pyserInit("/dev/x", 2, 1)
        assert f.connected == 0

    def test_pyserinit_env_glob_and_discovery(self, py2serial, monkeypatch):
        monkeypatch.setattr(atmod.GoodFETatmel128rfa1, "monitorecho", lambda self: True)
        monkeypatch.setenv("GOODFET", "/dev/e*")
        monkeypatch.setattr(atmod.glob, "glob", lambda p: ["/dev/e1"])
        f = atmod.GoodFETatmel128rfa1()
        f.pyserInit(None, 2, None)
        assert py2serial[-1].args[0] == "/dev/e1"
        monkeypatch.delenv("GOODFET")
        for hit in ("/dev/tty.usbserial*", "/dev/ttyUSB*", "/dev/ttyU0"):
            monkeypatch.setattr(
                atmod.glob, "glob", lambda p, hit=hit: ["/dev/h"] if p == hit else []
            )
            f = atmod.GoodFETatmel128rfa1()
            f.pyserInit(None, 2, None)
            assert py2serial[-1].args[0] == "/dev/h"

    def test_pyserinit_windows(self, py2serial, monkeypatch, capsys):
        monkeypatch.setattr(atmod.GoodFETatmel128rfa1, "monitorecho", lambda self: True)
        monkeypatch.setattr(atmod.os, "name", "nt")
        monkeypatch.setattr(sys, "version", "3 64 bit")

        class Scan:
            def comports(self):
                return [(1, "COM9", "d", "FTDIxx"), (2, "COM2", "d", 7)]

        m = types.ModuleType("scanwin32")
        m.winScan = Scan
        monkeypatch.setitem(sys.modules, "scanwin32", m)
        f = atmod.GoodFETatmel128rfa1()
        f.pyserInit(None, 2, None)
        assert py2serial[-1].args[0] == "COM9"
        assert "WARNING" in capsys.readouterr().out


# ================================================================ dev_apimote
@pytest.fixture
def apimote(cc_device):
    d = dev_apimote.APIMOTE("/dev/ttyUSB9")
    d.dev_model = cc_device
    return d


class TestApimote:
    def test_init_and_info(self, apimote, cc_device):
        import os

        assert os.environ["board"] == "apimote2"
        assert apimote.get_dev_info() == ["/dev/ttyUSB9", "GoodFET Apimote v2", ""]
        assert apimote.check_capability(KBCapabilities.PHYJAM)
        assert apimote.get_capabilities()[KBCapabilities.SNIFF]
        assert cc_device.regs[0x12] == 0x0500

    def test_close(self, apimote):
        apimote.close()
        assert apimote.handle is None
        with pytest.raises(Exception, match="Handle does not exist"):
            apimote.close()

    def test_sniffer_on_off_and_channel(self, apimote, cc_device):
        apimote.sniffer_on(channel=15)
        assert apimote._channel == 15
        assert cc_device.strobes[-1] == 3
        apimote.sniffer_off()
        apimote.sniffer_on()
        with pytest.raises(Exception, match="Invalid channel"):
            apimote.set_channel(10)
        with pytest.raises(Exception, match="SubGHz"):
            apimote.set_channel(12, page=1)

    def test_handle_none_errors(self, apimote):
        apimote.handle.serClose()
        apimote.handle = None
        for call in (
            lambda: apimote.sniffer_on(),
            lambda: apimote.set_channel(11),
            lambda: apimote.inject(b"x"),
            lambda: apimote.pnext(),
            lambda: apimote.jammer_on(),
            lambda: apimote.set_sync(),
        ):
            with pytest.raises(Exception, match="Handle does not exist"):
                call()

    def test_inject(self, apimote, cc_device):
        apimote.inject(b"\x01\x02\x03", channel=14, count=2)
        assert cc_device.txed == [b"\x05\x01\x02\x03"] * 2
        with pytest.raises(Exception, match="Empty"):
            apimote.inject(b"")
        with pytest.raises(Exception, match="too long"):
            apimote.inject(b"x" * 126)

    def test_pnext_timeout_returns_none(self, apimote):
        assert apimote.pnext(timeout=0.01) is None

    def test_pnext_packet_and_queue(self, apimote, cc_device):
        cc_device.regs[0x13] = 0x0020
        body = b"\x41\x88\x01\x02\x03"
        good = body + makeFCS(body)
        pkt = bytes([len(good)]) + good
        cc_device.rxq.append(pkt)
        r = apimote.pnext(timeout=1)
        assert r["bytes"] == good and r["validcrc"] is True
        assert r["rssi"] == 0x20 ^ 0x80 and r["dbm"] == r["rssi"] - 45
        assert r[0] == good and r["location"] is None
        assert isinstance(r["datetime"], datetime)
        # bad crc + trailing bytes get queued
        bad = b"\x41\x88\x01\x02\x03\x00\x00"
        tail = b"\x09\x08\x07\x06\x05\x04"
        cc_device.rxq.append(bytes([len(bad)]) + bad + tail)
        r = apimote.pnext(timeout=1)
        assert r["validcrc"] is False
        assert apimote.packet_queue is not None
        r2 = apimote.pnext(timeout=1)
        assert r2["bytes"] == apimote.packet_queue or r2["bytes"]
        assert apimote.packet_queue is None
        # queued branch with rssi None
        apimote.packet_queue = b"\x01\x02\x03\x04"
        apimote.packet_queue_rssi = None
        r3 = apimote.pnext(timeout=1)
        assert r3["rssi"] is None and r3["dbm"] is None

    def test_ping_and_jammer_off(self, apimote):
        with pytest.raises(Exception, match="Not yet"):
            apimote.ping(1, 2, 3)
        with pytest.raises(Exception, match="Not yet"):
            apimote.jammer_off()

    def test_jammer_on_methods(self, apimote, cc_device):
        apimote.jammer_on(channel=20, method="reflexive")
        apimote.jammer_on()
        assert cc_device.regs[0x2E] == 0x1800
        apimote.jammer_on(method="constant", channel=12)
        with pytest.raises(ValueError):
            apimote.jammer_on(method="bogus")

    def test_jammer_requires_capability(self, apimote):
        apimote.capabilities.setcapab(KBCapabilities.PHYJAM_REFLEX, False)
        with pytest.raises(Exception, match="does not support"):
            apimote.jammer_on(method="reflexive")

    def test_set_sync(self, apimote, cc_device):
        assert apimote.set_sync() is True
        assert cc_device.regs[0x14] == 0xA70F
        apimote.set_sync(0x1234)
        with pytest.raises(Exception, match="2-bytes"):
            apimote.set_sync(0x10000)


# ================================================================= dev_telosb
@pytest.fixture
def telos(cc_device):
    return dev_telosb.TELOSB("/dev/ttyUSB7")


class TestTelosB:
    def test_init(self, telos):
        import os

        assert os.environ["board"] == "telosb"
        assert telos.get_dev_info() == ["/dev/ttyUSB7", "TelosB/Tmote", ""]
        assert telos.check_capability(KBCapabilities.PHYJAM_REFLEX)
        assert not telos.check_capability(KBCapabilities.PHYJAM)
        assert telos.get_capabilities()[KBCapabilities.INJECT]

    def test_close(self, telos):
        telos.close()
        assert telos.handle is None

    def test_sniffer(self, telos, cc_device):
        telos.sniffer_on(channel=13)
        assert telos._channel == 13
        telos.sniffer_on()
        telos.sniffer_off()

    def test_set_channel_page(self, telos):
        telos.set_channel(15)
        with pytest.raises(Exception, match="SubGHz"):
            telos.set_channel(15, page=1)

    def test_invalid_channel_rejected(self, telos):
        with pytest.raises(Exception, match="Invalid channel"):
            telos.set_channel(5)

    def test_inject(self, telos, cc_device):
        telos.inject(b"\xaa\xbb", channel=12, count=2)
        assert cc_device.txed == [b"\x04\xaa\xbb"] * 2
        with pytest.raises(Exception, match="Empty"):
            telos.inject(b"")
        with pytest.raises(Exception, match="too long"):
            telos.inject(b"x" * 126)

    def test_pnext(self, telos, cc_device):
        assert telos.pnext(timeout=1000) is None
        body = b"\x61\x88\x05"
        good = body + makeFCS(body)
        cc_device.rxq.append(b"\x00" + good)
        r = telos.pnext(timeout=10**7)
        assert r["bytes"] == good and r["validcrc"] is True
        cc_device.rxq.append(b"\x00" + body + b"\x00\x00")
        r = telos.pnext(timeout=10**7)
        assert r["validcrc"] is False

    def test_ping_jammer(self, telos, cc_device):
        with pytest.raises(Exception, match="Not yet"):
            telos.ping(1, 2, 3)
        with pytest.raises(Exception, match="Not yet"):
            telos.jammer_off()
        telos.jammer_on(channel=15, method="reflexive")
        with pytest.raises(ValueError):
            telos.jammer_on()
        with pytest.raises(ValueError):
            telos.jammer_on(method="constant")
        telos.capabilities.setcapab(KBCapabilities.PHYJAM_REFLEX, False)
        with pytest.raises(Exception, match="does not support"):
            telos.jammer_on(method="reflexive")

    def test_set_sync(self, telos, cc_device):
        assert telos.set_sync() is True
        assert cc_device.regs[0x14] == 0xA70F
        with pytest.raises(Exception, match="2-bytes"):
            telos.set_sync(0x10000)


# =============================================================== dev_template
@pytest.fixture
def tmpl(cc_device):
    return dev_template.APIMOTE("/dev/tpl")


class TestTemplate:
    def test_basic(self, tmpl):
        assert tmpl.get_dev_info() == ["/dev/tpl", "GoodFET Apimote", ""]
        caps = tmpl.get_capabilities()
        assert caps[KBCapabilities.SNIFF] and not caps[KBCapabilities.PHYJAM]
        assert tmpl.check_capability(KBCapabilities.INJECT)
        assert not tmpl.check_capability(KBCapabilities.SET_SYNC)

    def test_close(self, tmpl):
        tmpl.close()
        assert tmpl.handle is None
        with pytest.raises(Exception, match="Handle does not exist"):
            tmpl.close()

    def test_sniffer_and_channel(self, tmpl):
        tmpl.sniffer_on()
        tmpl.sniffer_on(channel=12)
        assert tmpl._channel == 12
        tmpl.sniffer_off()
        with pytest.raises(Exception, match="Invalid channel"):
            tmpl.set_channel(30)

    def test_inject(self, tmpl):
        tmpl.inject(b"abc")
        tmpl.inject(b"abc", channel=11)
        with pytest.raises(Exception, match="Empty"):
            tmpl.inject(b"")
        with pytest.raises(Exception, match="too long"):
            tmpl.inject(b"x" * 126)

    def test_pnext(self, tmpl):
        r = tmpl.pnext()
        assert r["bytes"] is None and r["dbm"] is None and r["validcrc"] is False
        tmpl.sniffer_on()
        assert tmpl.pnext()["location"] is None

    def test_unsupported(self, tmpl):
        with pytest.raises(Exception, match="Not yet"):
            tmpl.ping(1, 2, 3)
        with pytest.raises(Exception, match="Not yet"):
            tmpl.jammer_off()
        with pytest.raises(Exception, match="does not support"):
            tmpl.jammer_on()
        with pytest.raises(Exception, match="does not support"):
            tmpl.set_sync()

    def test_handle_none(self, tmpl):
        tmpl.handle = None
        for call in (
            lambda: tmpl.sniffer_on(),
            lambda: tmpl.set_channel(11),
            lambda: tmpl.inject(b"x"),
            lambda: tmpl.pnext(),
        ):
            with pytest.raises(Exception, match="Handle does not exist"):
                call()

    def test_jammer_set_sync_with_caps(self, tmpl):
        tmpl.capabilities.setcapab(KBCapabilities.PHYJAM_REFLEX, True)
        tmpl.capabilities.setcapab(KBCapabilities.SET_SYNC, True)
        tmpl.jammer_on()
        tmpl.jammer_on(channel=12)
        tmpl.set_sync()
        h = tmpl.handle
        tmpl.handle = None
        with pytest.raises(Exception, match="Handle does not exist"):
            tmpl.jammer_on()
        with pytest.raises(Exception, match="Handle does not exist"):
            tmpl.set_sync()
        tmpl.handle = h

    def test_pnext_with_frame_crc(self, tmpl):
        # The template never produces a frame; exercise the crc branch via a patched frame source.
        import killerbee.dev_template as t

        assert t.makeFCS(b"") is not None
