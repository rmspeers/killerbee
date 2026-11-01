"""Tests for killerbee.GoodFET (client library) using a scripted fake serial port."""

import struct
import sys
import types

import pytest

from killerbee import GoodFET as gf


def frame(app, verb, data=b""):
    data = bytes(data)
    return bytes([app, verb]) + struct.pack("<H", len(data)) + data


class FakeSerial:
    """Scripted stand-in for serial.Serial speaking the GoodFET frame format.

    * ``rx``       bytes the host will read.
    * ``responder`` optional callable(app, verb, data) -> bytes appended to rx
                    each time a complete command frame has been written.
    * ``mute``     number of initial read() calls that return b"" (timeouts).
    * ``fill``     if set, read(n) returns that byte repeated once rx is empty.
    """

    PARITY_NONE = "N"

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.timeout = kwargs.get("timeout")
        self.rx = bytearray()
        self.responder = None
        self.mute = 0
        self.fill = None
        self.tx = bytearray()
        self.pending = bytearray()
        self.calls = []
        self.cts = 1
        self.closed = False
        self.frames = []
        self._baud = 115200

    def read(self, n=1):
        if self.mute > 0:
            self.mute -= 1
            return b""
        out = bytes(self.rx[:n])
        del self.rx[:n]
        if len(out) < n and self.fill is not None:
            out += bytes([self.fill]) * (n - len(out))
        return out

    def write(self, data):
        data = bytes(data)
        self.tx += data
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
        self.calls.append("flushInput")

    def flushOutput(self):
        self.calls.append("flushOutput")

    def setRTS(self, v):
        self.calls.append(("RTS", v))

    def setDTR(self, v):
        self.calls.append(("DTR", v))

    def getCTS(self):
        return self.cts

    @property
    def baudrate(self):
        return self._baud

    @baudrate.setter
    def baudrate(self, b):
        # pyserial 3 has no setBaudrate(); the property is the only API.
        self._baud = b
        self.calls.append(("baud", b))

    def inWaiting(self):
        return len(self.rx)


BANNER = frame(0x00, 0x7F, b"http://goodfet.sf.net/")


def ack(app, verb, payload):
    return frame(app, verb, b"")


@pytest.fixture(autouse=True)
def _nosleep(monkeypatch):
    monkeypatch.setattr(gf.time, "sleep", lambda s: None)
    for var in ("GOODFET", "board", "platform"):
        monkeypatch.setenv(var, "x")
        monkeypatch.delenv(var)


@pytest.fixture
def fet():
    f = gf.GoodFET()
    f.serialport = FakeSerial()
    return f


# ---------------------------------------------------------------- module level
def test_getclient_branches(monkeypatch):
    # Sibling modules are imported relatively (killerbee.GoodFETxx); stub the
    # ones that do not exist in the package.
    for mod in (
        "GoodFETCC",
        "GoodFETAVR",
        "GoodFETSPI",
        "GoodFETMSP430",
        "GoodFETNRF",
        "GoodFETCCSPI",
    ):
        m = types.ModuleType("killerbee." + mod)
        setattr(m, mod, lambda mod=mod: "inst-" + mod)
        monkeypatch.setitem(sys.modules, "killerbee." + mod, m)
    assert isinstance(gf.getClient(), gf.GoodFET)
    assert isinstance(gf.getClient("monitor"), gf.GoodFET)
    assert gf.getClient("cc") == "inst-GoodFETCC"
    assert gf.getClient("cc51") == "inst-GoodFETCC"
    assert gf.getClient("cc2420") == "inst-GoodFETCCSPI"
    assert gf.getClient("ccspi") == "inst-GoodFETCCSPI"
    assert gf.getClient("avr") == "inst-GoodFETAVR"
    assert gf.getClient("spi") == "inst-GoodFETSPI"
    assert gf.getClient("msp430") == "inst-GoodFETMSP430"
    assert gf.getClient("nrf") == "inst-GoodFETNRF"
    with pytest.raises(SystemExit):
        gf.getClient("bogus")


def test_getclient_real_imports():
    from killerbee import GoodFETAVR, GoodFETCCSPI

    assert isinstance(gf.getClient("GoodFET"), gf.GoodFET)
    assert isinstance(gf.getClient("avr"), GoodFETAVR.GoodFETAVR)
    assert isinstance(gf.getClient("ccspi"), GoodFETCCSPI.GoodFETCCSPI)


def test_symbol_table():
    st = gf.SymbolTable()
    st.define(0x1234, "kb_test_sym", "comment")
    assert st.get("kb_test_sym") == 0x1234
    # Unknown names fall through to eval()
    assert st.get("1+2") == 3
    f = gf.GoodFET()
    assert f.name2adr("kb_test_sym") == 0x1234


def test_misc_simple(fet, capsys, monkeypatch):
    fet.timeout()
    assert "timeout" in capsys.readouterr().out
    m = types.ModuleType("killerbee.GoodFETConsole")
    m.GoodFETConsole = lambda c: ("console", c)
    monkeypatch.setitem(sys.modules, "killerbee.GoodFETConsole", m)
    assert fet.getConsole() == ("console", fet)
    fet.serClose()
    assert fet.serialport.closed


# ------------------------------------------------------------------ connection
@pytest.fixture
def patch_serial(monkeypatch):
    import serial

    made = []

    def factory(*a, **k):
        s = FakeSerial(*a, **k)
        s.rx += BANNER + ack(0, 0xB1, b"")
        s.responder = None
        made.append(s)
        return s

    monkeypatch.setattr(serial, "Serial", factory, raising=True)
    return made


def test_serinit_default_connect(patch_serial, monkeypatch):
    f = gf.GoodFET()
    monkeypatch.setattr(gf.glob, "glob", lambda p: [])
    f.serInit(port="/dev/fake0")
    assert f.connected == 1
    assert f.serialport.args[0] == "/dev/fake0"
    assert f.serialport.args[1] == 115200
    assert f.serialport.timeout == 12
    assert ("DTR", 0) in f.serialport.calls


def test_serinit_env_port_glob_and_verbose(patch_serial, monkeypatch, capsys):
    monkeypatch.setenv("GOODFET", "/dev/kbfake*")
    monkeypatch.setattr(gf.glob, "glob", lambda p: ["/dev/kbfake1"])
    f = gf.GoodFET()
    f.verbose = True
    f.serInit()
    assert f.serialport.args[0] == "/dev/kbfake*"
    assert "Connected after" in capsys.readouterr().out


def test_pyserinit_env_port_glob_match(patch_serial, monkeypatch):
    monkeypatch.setenv("GOODFET", "/dev/kbg*")
    monkeypatch.setattr(gf.glob, "glob", lambda p: ["/dev/kbg7"])
    f = gf.GoodFET()
    f.pyserInit(None, 2, None)
    assert f.serialport.args[0] == "/dev/kbg7"


def test_symbol_table_db_error(monkeypatch):
    import sqlite3

    monkeypatch.setattr(gf.SymbolTable, "db", sqlite3.connect(":memory:"))
    assert gf.SymbolTable.__new__(gf.SymbolTable).get("7*6") == 42


def test_pyserinit_env_port_no_glob_match(patch_serial, monkeypatch):
    monkeypatch.setenv("GOODFET", "/dev/kbnone")
    monkeypatch.setattr(gf.glob, "glob", lambda p: [])
    f = gf.GoodFET()
    f.pyserInit(None, 2, None)
    assert f.serialport.args[0] == "/dev/kbnone"


@pytest.mark.parametrize("hit", ["/dev/tty.usbserial*", "/dev/ttyUSB*", "/dev/ttyU0", None])
def test_pyserinit_autodiscovery(patch_serial, monkeypatch, hit):
    def fake_glob(p):
        return ["/dev/found"] if p == hit else []

    monkeypatch.setattr(gf.glob, "glob", fake_glob)
    f = gf.GoodFET()
    f.pyserInit(None, 2, None)
    assert f.serialport.args[0] == ("/dev/found" if hit else None)


def test_pyserinit_windows(patch_serial, monkeypatch, capsys):
    monkeypatch.setattr(gf.os, "name", "nt")
    monkeypatch.setattr(gf.glob, "glob", lambda p: [])
    monkeypatch.setattr(sys, "version", "3.13 64 bit")

    class Scan:
        def comports(self):
            return [(1, "COM3", "x", "FTDI123"), (2, "COM4", "y", "OTHER"), (3, "COM5", "z", 5)]

    m = types.ModuleType("scanwin32")
    m.winScan = Scan
    monkeypatch.setitem(sys.modules, "scanwin32", m)
    f = gf.GoodFET()
    f.pyserInit(None, 2, None)
    assert f.serialport.args[0] == "COM3"
    assert "WARNING" in capsys.readouterr().out


def test_pyserinit_arduino_baud(patch_serial, monkeypatch):
    monkeypatch.setenv("board", "arduino")
    f = gf.GoodFET()
    f.pyserInit("/dev/x", 2, None)
    assert f.serialport.args[1] == 19200
    monkeypatch.delenv("board")
    monkeypatch.setenv("platform", "arduino")
    f2 = gf.GoodFET()
    f2.pyserInit("/dev/x", 2, None)
    assert f2.serialport.args[1] == 19200


@pytest.mark.parametrize("board", ["telosb", "z1", "apimote1", "apimote"])
def test_pyserinit_board_resets(patch_serial, monkeypatch, board):
    monkeypatch.setenv("board", board)
    f = gf.GoodFET()
    f.pyserInit("/dev/x", 2, None)
    calls = f.serialport.calls
    assert f.connected == 1
    if board == "apimote1" or board == "apimote":
        assert ("RTS", 0) in calls
    else:
        assert "flushInput" in calls or ("RTS", 1) in calls or ("DTR", 0) in calls


def test_pyserinit_attemptlimit(monkeypatch, capsys):
    import serial

    made = []
    monkeypatch.setattr(
        serial, "Serial", lambda *a, **k: made.append(FakeSerial(*a, **k)) or made[-1]
    )
    f = gf.GoodFET()
    f.pyserInit("/dev/x", 2, 3)  # never connects; returns after limit
    assert f.connected == 0
    assert "missing info flash" in capsys.readouterr().out
    assert made[0].timeout == 0.2


def test_pyserinit_many_attempts_return(monkeypatch, capsys):
    import serial

    monkeypatch.setattr(serial, "Serial", FakeSerial)
    f = gf.GoodFET()
    f.pyserInit("/dev/x", 2, 112)
    out = capsys.readouterr().out
    assert "Tried 100 times" in out
    assert f.verbose is True
    assert "." in out


def _slow_connect_serial(monkeypatch, mute_reads, echo=True):
    import serial

    made = []

    def factory(*a, **k):
        s = FakeSerial(*a, **k)
        s.mute = mute_reads
        s.rx += BANNER
        if echo:

            def responder(app, verb, payload):
                if (app, verb) == (0, 0x81):
                    return frame(0, 0x81, payload)
                if (app, verb) == (0, 0x02):  # monitor peek8
                    return frame(0, 0x02, b"\x12")
                return frame(app, verb, b"")

            s.responder = responder
        made.append(s)
        return s

    monkeypatch.setattr(serial, "Serial", factory)
    return made


def test_pyserinit_after_100_attempts_arduino(monkeypatch, capsys):
    monkeypatch.setenv("board", "arduino")
    _slow_connect_serial(monkeypatch, 260)
    f = gf.GoodFET()
    f.pyserInit("/dev/x", 2, None)
    assert f.connected == 1
    out = capsys.readouterr().out
    assert "Tried 100 times" in out


def test_pyserinit_after_100_attempts_comm_error(monkeypatch, capsys):
    monkeypatch.setenv("board", "arduino")
    made = _slow_connect_serial(monkeypatch, 260, echo=False)
    f = gf.GoodFET()
    f.verbose = True
    f.pyserInit("/dev/x", 2, None)
    assert "Comm error" in capsys.readouterr().out


def test_pyserinit_after_100_attempts_real_infostring(monkeypatch):
    _slow_connect_serial(monkeypatch, 260)
    f = gf.GoodFET()
    f.pyserInit("/dev/x", 2, None)
    assert f.connected == 1


# ---------------------------------------------------------- TelosB / Z1 helpers
def test_telos_helpers(fet):
    fet.telosSetSCL(1)
    fet.telosSetSDA(0)
    fet.telosI2CStart()
    fet.telosI2CStop()
    fet.telosI2CWriteByte(0xA5)
    fet.telosI2CWriteCmd(0, 1)
    calls = fet.serialport.calls
    assert ("RTS", False) in calls and ("DTR", True) in calls


def test_telosb_reset(fet):
    fet.telosBReset()
    assert "flushInput" in fet.serialport.calls
    fet.serialport.calls.clear()
    fet.telosBReset(invokeBSL=1)
    assert "flushInput" in fet.serialport.calls


def test_bsl_reset_z1_and_picrom(fet):
    fet.serialport.cts = 1
    fet.bslResetZ1(invokeBSL=0)
    fet.bslResetZ1(invokeBSL=1)
    assert fet.writepicROM(0xA5, 0x3C) == 0
    fet.serialport.cts = 0
    assert fet.writepicROM(0xA5, 0xFF) == 0xFF
    fet.serialport.cts = 1
    assert fet.readpicROM(0x12) == 0xFF
    assert fet.picROMfastclock(1) == 1


# ------------------------------------------------------------------ writecmd/readcmd
def test_writecmd_basic(fet):
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x01\x02")
    out = fet.writecmd(0x40, 0x05, 3, [1, 2, 3, 4])
    assert fet.serialport.frames == [(0x40, 0x05, b"\x01\x02\x03")]
    assert out == bytearray(b"\x01\x02")
    assert fet.app == 0x40 and fet.verb == 0x05 and fet.count == 2


def test_writecmd_verbose_and_silent(fet, capsys):
    fet.verbose = True
    fet.serialport.rx += frame(1, 2, b"ab")
    fet.writecmd(1, 2, 0)
    out = capsys.readouterr().out
    assert "Tx:" in out and "Rx:" in out
    fet.besilent = 1
    assert fet.writecmd(1, 2) == bytearray([0])


def test_readcmd_debug_frames(fet, capsys):
    s = fet.serialport
    s.rx += frame(0xFF, 0xFF, b"hello")
    s.rx += frame(0xFF, 0xFE, struct.pack("<H", 0x1234))
    s.rx += frame(0xFF, 0xFD, b"")
    s.rx += frame(0xFF, 0x01, b"")
    s.rx += frame(0x00, 0x00)[:2] + bytes([0x00, 0x00, 0x00]) + b""  # app 0, verb 0 then 0x00 skip
    s.rx += bytes([0x05, 0x00, 0x00])  # real verb 5, count 0 (after skip)
    out = fet.readcmd()
    text = capsys.readouterr().out
    assert "# DEBUG" in text and "0x1234" in text and "NOP" in text
    assert fet.app == 0 and fet.verb == 5
    assert out == bytearray()


def test_writecmd_no_data_is_zero_padded(fet):
    fet.besilent = 1
    fet.writecmd(0x40, 0x05, 3)  # data omitted
    fet.writecmd(0x40, 0x06, 4, b"\x01")  # data too short
    fet.writecmd(0x40, 0x07, 1, b"\x09\x08")  # data truncated to count
    assert fet.serialport.frames == [
        (0x40, 0x05, b"\0\0\0"),
        (0x40, 0x06, b"\x01\0\0\0"),
        (0x40, 0x07, b"\x09"),
    ]


def test_readcmd_debug_3byte_and_partial_header(fet, capsys):
    s = fet.serialport
    s.rx += frame(0xFF, 0xFE, b"\x01\x02\x03") + frame(0x10, 0x01, b"ok")
    assert fet.readcmd() == bytearray(b"ok")
    assert "0x30201" in capsys.readouterr().out
    fet.connected = 0
    s.rx += bytes([0x10, 0x01, 0x05])  # truncated count field: timeout
    assert fet.readcmd() == bytearray(b"ok")


def test_readcmd_timeout(fet, capsys):
    fet.data = bytearray(b"old")
    fet.connected = 1
    assert fet.readcmd() == bytearray(b"old")
    assert "timed out" in capsys.readouterr().out
    fet.connected = 0
    assert fet.readcmd() == bytearray(b"old")


# ------------------------------------------------------------------ glitch & monitor
def test_glitch_functions(fet, capsys):
    s = fet.serialport
    s.responder = lambda a, v, d: frame(a, v, b"\x00\x00")
    fet.glitchApp(0x32)
    fet.glitchVerb(0x32, 0x20, [1, 2])
    fet.glitchVerb(0x32, 0x20, None)
    fet.glitchVoltages()
    fet.glitchRate()
    assert [f[1] for f in s.frames] == [0x80, 0x81, 0x81, 0x90, 0x91]
    fet.APP = 0x32
    fet.glitchstart()
    assert s.frames[-1][:2] == (0x71, 0x81)


def test_glitch_time(fet, capsys):
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x10\x01")
    assert fet.glitchTime(0x32, 0x20, None) == 0x110
    assert "Timed to be 272" in capsys.readouterr().out
    fet.APP = 0x32
    assert fet.glitchstarttime() == 0x110


def test_monitor_simple_commands(fet, capsys):
    s = fet.serialport
    s.responder = ack
    fet.silent(1)
    assert fet.besilent == 1
    fet.silent(0)
    fet.mon_connected()
    assert fet.connected == 1
    fet.out(1)
    fet.dir(2)
    fet.call(0x1234)
    fet.execute([1, 2])
    fet.monitor_ram_pattern()
    verbs = [f[1] for f in s.frames]
    assert verbs == [0xB0, 0xB0, 0xB1, 0xA1, 0xA0, 0x30, 0x31, 0x90]
    assert s.frames[5][2] == b"\x34\x12"


def test_monpeek_patched(fet, monkeypatch):
    mem = {0x10: 0x34, 0x11: 0x12}
    monkeypatch.setattr(fet, "MONpeek8", lambda a: mem.get(a, 0))
    assert fet.MONpeek16(0x10) == 0x1234
    assert gf.GoodFET.peek(fet, 0x10) == 0x1234
    assert fet.peek8(0x10) == 0x34
    assert fet.peek16(0x10) == 0x1234
    assert fet.peek32(0x10) == 0x1234
    assert fet.peekblock(0x10, 2) == [0x34, 0x12]


def test_monpeek8_real_frame(fet):
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x7f")
    assert fet.MONpeek8(0x1234) == 0x7F
    assert fet.serialport.frames[-1] == (0, 0x02, b"\x34\x12")


def test_pokebyte_works(fet):
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x07")
    assert fet.pokebyte(0x1234, 7) == 7
    assert fet.serialport.frames[-1] == (0, 0x03, b"\x34\x12\x07")


def test_pokebyte_poke16_paths(fet, monkeypatch):
    writes = []
    monkeypatch.setattr(fet, "pokebyte", lambda a, v, m="vn": writes.append((a, v)))
    assert fet.MONpoke16(0x20, 0xABCD) == 0xABCD
    assert writes == [(0x20, 0xCD), (0x20, 0xAB)]
    fet.poke16(0x20, 0x0102)
    fet.pokeblock(0x30, [1, 2, 3])
    assert writes[-3:] == [(0x30, 1), (0x31, 2), (0x32, 3)]
    fet.monitorsetclock(0x1234)
    assert writes[-2][0] == 0x56


def test_peekbysym_pokebysym(fet, monkeypatch):
    fet.symbols.define(0x56, "kb_clk_sym")
    monkeypatch.setattr(fet, "peek8", lambda a, m="vn": (a, m))
    monkeypatch.setattr(fet, "pokebyte", lambda a, v, m="vn": ("poked", a, v))
    assert fet.peekbysym("kb_clk_sym") == (0x56, "data")
    assert fet.pokebysym("kb_clk_sym", 9) == ("poked", 0x56, 9)


def test_dumpmem(fet, monkeypatch, capsys):
    monkeypatch.setattr(fet, "MONpeek16", lambda a: a * 2)
    fet.dumpmem(0, 4)
    assert "0002 0004" in capsys.readouterr().out


def test_ram_depth_works(fet):
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x01\x02")
    assert fet.monitor_ram_depth() == 0x0201


def test_secrets_and_stubs(fet, capsys):
    fet.setsecret(1)
    fet.eeprompeek(0)
    with pytest.raises(SystemExit):
        fet.getsecret()
    fet.lock()
    fet.erase()
    assert fet.setup() is None and fet.start() is None
    fet.test()
    fet.status()
    fet.halt()
    fet.resume()
    assert fet.getpc() == 0xDEAD
    fet.flash("x")
    fet.dump("x")
    assert fet.loadsymbols() is None
    out = capsys.readouterr().out
    assert "Locking Unsupported" in out and "Flash not implemented" in out


def test_set_baud_and_findbaud(fet, capsys):
    fet.setBaud(2)
    s = fet.serialport
    assert ("baud", 19200) in s.calls
    assert s.baudrate == 19200
    assert bytes(s.tx).startswith(bytes([0, 0x80, 1, 2]))
    s.fill = 0x41
    fet.findbaud()
    assert [c for c in s.calls if isinstance(c, tuple)].count(("baud", 9600)) >= 1
    assert fet.readbyte() == 0x41


def test_monitorecho(fet, capsys):
    fet.serialport.responder = lambda a, v, d: frame(a, v, d)
    assert fet.monitorecho() == 1
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"junk")
    fet.verbose = True
    assert fet.monitorecho() == 0
    assert "Comm error" in capsys.readouterr().out
    fet.verbose = False
    assert fet.monitorecho() == 0


def test_testleds(fet, capsys):
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x03")
    assert fet.testleds() == 1
    assert "Flashed 3 LED" in capsys.readouterr().out
    fet.serialport.responder = lambda a, v, d: frame(a, v, b"\x03\x04")
    assert fet.testleds() == 1
    assert "Unable to process" in capsys.readouterr().out


def test_monitor_info_and_clock_arduino(fet, monkeypatch, capsys):
    monkeypatch.setenv("board", "arduino")
    assert fet.monitorgetclock() == 0xDEAD
    assert fet.monitorclocking() == "0xdead"
    assert fet.infostring() == "Arduino"
    assert fet.monitor_info() == 1
    assert "Arduino" in capsys.readouterr().out


def test_clock_and_infostring_nonarduino_patched(fet, monkeypatch):
    monkeypatch.setattr(fet, "MONpeek16", lambda a: 0x4321)
    monkeypatch.setattr(fet, "MONpeek8", lambda a: 0x0A if a == 0xFF0 else 0x0B)
    assert fet.monitorgetclock() == 0x4321
    assert fet.infostring() == "0a0b"


def test_monitor_list_apps(fet, monkeypatch, capsys):
    monkeypatch.setenv("board", "arduino")
    s = fet.serialport
    s.responder = lambda a, v, d: (
        frame(0, 0x82, b"Jan 1 2020")
        + frame(0, 0x82, b"app1")
        + frame(0, 0x82, b"app2")
        + frame(0, 0x82, b"")
        if v == 0x82
        else b""
    )
    assert fet.monitor_list_apps(True) == 1
    out = capsys.readouterr().out
    assert "Build Date" in out and "app2" in out
    assert fet.besilent is False or fet.besilent == 0


def test_monitortest(fet, monkeypatch, capsys):
    monkeypatch.setattr(fet, "monitorclocking", lambda: "0x0000")
    monkeypatch.setattr(fet, "MONpeek16", lambda a: 0x0C04)
    monkeypatch.setattr(fet, "pokebyte", lambda *a, **k: 0)
    monkeypatch.setattr(fet, "MONpeek8", lambda a: 0)
    monkeypatch.setattr(fet, "monitorecho", lambda: 1)
    fet.monitortest()
    assert "Self-test complete" in capsys.readouterr().out
    # Error branches
    n = {"c": 0}

    def bad16(a):
        return 0x1111

    monkeypatch.setattr(fet, "MONpeek16", bad16)
    monkeypatch.setattr(fet, "MONpeek8", lambda a: 1)
    monkeypatch.setattr(fet, "monitorecho", lambda: 0)
    fet.monitortest()
    out = capsys.readouterr().out
    assert "ERROR Fetched" in out and "P1OUT not cleared" in out and "Echo test failed" in out
