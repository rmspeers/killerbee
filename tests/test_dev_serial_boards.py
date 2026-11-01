"""Tests for dev_freakduino and dev_zigduino with scripted fake serial / GoodFET handles."""
import struct
from datetime import datetime, time as dttime

import pytest

from killerbee import dev_freakduino as fd
from killerbee import dev_zigduino as zd
from killerbee.kbutils import KBCapabilities


class Py2Serial:
    """Fake pyserial object that speaks str (as the Freakduino driver expects)."""

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.timeout = kwargs.get("timeout")
        self.rx = ""
        self.tx = []
        self.closed = False
        self.empty_reads = 0

    def read(self, n=1):
        if not self.rx:
            self.empty_reads += 1
            if self.empty_reads > 2000:
                raise RuntimeError("fake serial exhausted")
            return ""
        out, self.rx = self.rx[:n], self.rx[n:]
        return out

    def readline(self, eol="\n"):
        i = self.rx.find(eol)
        if i < 0:
            out, self.rx = self.rx, ""
        else:
            out, self.rx = self.rx[:i + 1], self.rx[i + 1:]
        return out

    def write(self, data):
        self.tx.append(data)

    def flush(self):
        pass

    def flushInput(self):
        pass

    def inWaiting(self):
        return len(self.rx)

    def close(self):
        self.closed = True


@pytest.fixture
def freak(monkeypatch):
    monkeypatch.setattr(fd.time, "sleep", lambda s: None)
    monkeypatch.setattr(fd.serial, "Serial", Py2Serial)
    return fd.FREAKDUINO("/dev/ttyUSB5")


# ================================================================= Freakduino
class TestFreakduino:
    def test_init_info_caps(self, freak):
        assert freak.get_dev_info() == ["/dev/ttyUSB5", "Dartmouth Freakduino", ""]
        assert freak.handle.kwargs["baudrate"] == 57600
        assert freak.check_capability(KBCapabilities.SNIFF)
        assert freak.get_capabilities()[KBCapabilities.SETCHAN]
        assert not freak.check_capability(KBCapabilities.INJECT)

    def test_close(self, freak):
        h = freak.handle
        freak.close()
        assert h.closed and freak.handle is None

    def test_sniffer_on_off_channel_dump(self, freak):
        h = freak.handle
        freak.sniffer_on(channel=14)
        assert freak.mode == fd.MODE_SNIFF
        assert "".join(h.tx).count("S") == 2
        assert "C!C 14" in "".join(h.tx) or ("C!C %d" % 14) in h.tx
        freak.sniffer_off()
        assert freak.mode == fd.MODE_NONE
        freak.eeprom_dump()
        assert "C!D" in h.tx
        freak.sniffer_on()

    def test_set_channel_requires_cap(self, freak):
        freak.set_channel(20)
        assert freak._channel == 20
        freak.capabilities.setcapab(KBCapabilities.SETCHAN, False)
        with pytest.raises(Exception, match="does not support"):
            freak.set_channel(20)

    @pytest.mark.xfail(strict=False, reason="channel check uses 'or' (>=10 or <=26): out-of-range never rejected; "
                                            "also page argument is ignored")
    def test_set_channel_invalid(self, freak):
        with pytest.raises(Exception, match="Invalid channel"):
            freak.set_channel(40)

    def test_inject(self, freak):
        freak.capabilities.setcapab(KBCapabilities.INJECT, True)
        with pytest.raises(Exception, match="Empty"):
            freak.inject("")
        with pytest.raises(Exception, match="too long"):
            freak.inject("x" * 126)
        freak.inject("abc", count=0)
        with pytest.raises(Exception, match="Not yet implemented"):
            freak.inject("abc", channel=12)
        with pytest.raises(TypeError):   # py3: bytes + str join
            freak.inject(b"abc")

    def test_inject_requires_cap(self, freak):
        with pytest.raises(Exception, match="does not support"):
            freak.inject("abc")

    def test_ping_jammer(self, freak):
        with pytest.raises(Exception, match="Not yet"):
            freak.ping(1, 2, 3)
        with pytest.raises(Exception, match="Not yet"):
            freak.jammer_off()
        with pytest.raises(Exception, match="does not support"):
            freak.jammer_on()

    def test_set_channel_page_and_pnext_autostart(self, freak, monkeypatch):
        with pytest.raises(Exception, match="SubGHz"):
            freak.set_channel(12, page=1)
        monkeypatch.setattr(fd, "makeFCS", lambda d: "ok")
        freak._FREAKDUINO__stream_open = False
        assert freak.pnext() is None
        assert freak.mode == fd.MODE_SNIFF

    def test_jammer_on_with_undefined_names_patched(self, freak, monkeypatch):
        monkeypatch.setattr(fd, "RZ_CMD_MODE_AC", 1, raising=False)
        freak.capabilities.setcapab(KBCapabilities.PHYJAM, True)
        freak._FREAKDUINO__cmdmode = 0
        freak._set_mode = lambda m: setattr(freak, "_FREAKDUINO__cmdmode", m)
        with pytest.raises(Exception, match="Not yet implemented"):
            freak.jammer_on(channel=12)

    @pytest.mark.xfail(strict=False,
                       reason="jammer_on references undefined self.__cmdmode / RZ_CMD_MODE_AC")
    def test_jammer_on_with_cap(self, freak):
        freak.capabilities.setcapab(KBCapabilities.PHYJAM, True)
        with pytest.raises(Exception, match="Not yet implemented"):
            freak.jammer_on(channel=12)

    # pnext_rec -----------------------------------------------------------
    @pytest.fixture
    def parse(self, freak, monkeypatch):
        monkeypatch.setattr(fd, "makeFCS", lambda d: "ok")
        freak.getCaptureDateTime = lambda data: "dt"
        return freak

    def test_pnext_requires_sniffer_on_first(self, freak):
        # __stream_open is only created in sniffer_on(); plain pnext() hits AttributeError
        with pytest.raises(AttributeError):
            freak.pnext()

    def test_pnext_after_sniffer_on_packet(self, parse):
        parse.sniffer_on()
        parse.handle.rx = "R!" + "\x30" + "!tm!len!hello;ok"[:-3] + ";"
        # frame is 'hello' -> crc compare uses patched makeFCS ("ok")
        r = parse.pnext(timeout=5)
        assert r["bytes"] == "hello" and r["validcrc"] is False
        assert r["rssi"] == 0x30 and r["datetime"] == "dt" and r["dbm"] is None
        assert r["location"] == (None, None, None)
        assert parse.handle.timeout == 5

    def test_pnext_rec_valid_crc(self, parse):
        parse.handle.rx = "R!\x01!a!b!xxok;"
        # frame 'xxok' -> frame[-2:] == 'ok' == patched makeFCS
        r = parse.pnext_rec()
        assert r["validcrc"] is True and r[1] is True

    def test_pnext_rec_parse_error(self, parse, capsys):
        parse.handle.rx = "R!\x01!onlytwo;"
        assert parse.pnext_rec() is None
        assert "Error parsing" in capsys.readouterr().out

    def test_pnext_rec_unknown_and_timeout(self, parse):
        parse.handle.rx = "Zjunk"
        assert parse.pnext_rec() is None
        parse.handle.rx = "R?"
        assert parse.pnext_rec() is None
        assert parse.pnext_rec() is None

    def test_pnext_rec_location(self, parse):
        seen = []
        parse.processLocationUpdate = lambda d: seen.append(d)
        parse.handle.rx = "L!abcd;"
        assert parse.pnext_rec() is None
        assert seen == ["abcd"]
        parse.handle.rx = "L?"
        parse.pnext_rec()

    def test_pnext_rec_done_reading(self, parse):
        parse.handle.rx = "[{[ DONE READING BACK ALL LOGGED DATA ]}]"[1:] if False else \
            "[" + "{[ DONE READING BACK ALL LOGGED DATA ]}]"
        # read() after '[' consumes 40 chars -> must match the sentinel string
        with pytest.raises(StopIteration):
            parse.pnext_rec()
        parse.handle.rx = "[" + "x" * 40
        assert parse.pnext_rec() is None

    def test_pnext_rec_bytes_from_real_pyserial(self, parse):
        # Real pyserial returns bytes, so "R" never matches: documented py3 limitation
        class BytesSerial(Py2Serial):
            def read(self, n=1):
                s = super().read(n)
                return s.encode("latin-1") if s else None
        parse.handle = BytesSerial()
        parse.handle.rx = "R!\x01!a!b!xxok;"
        assert parse.pnext_rec() is None

    @pytest.mark.xfail(strict=False, reason="py3: serial returns bytes, driver compares to str; no packet is ever parsed")
    def test_pnext_rec_real_bytes_parsed(self, freak, monkeypatch):
        class BytesSerial(Py2Serial):
            def read(self, n=1):
                s = super().read(n)
                return s.encode("latin-1")
        freak.handle = BytesSerial()
        freak.handle.rx = "R!\x01!1!4!abcd;"
        assert freak.pnext_rec() is not None

    # time / location --------------------------------------------------------
    def test_capture_datetime_ok(self, freak, monkeypatch):
        class S:
            @staticmethod
            def unpack(f, d):
                return (12345678,)
        monkeypatch.setattr(fd, "struct", S)
        freak.date = datetime(2020, 1, 2).date()
        dt = freak.getCaptureDateTime([0, "x"])
        assert dt == datetime(2020, 1, 2, 12, 34, 56, 78)

    def test_capture_datetime_zero_time_uses_now(self, freak, monkeypatch):
        class S:
            @staticmethod
            def unpack(f, d):
                return (0,)
        monkeypatch.setattr(fd, "struct", S)
        freak.date = datetime(2020, 1, 2).date()
        dt = freak.getCaptureDateTime([0, "x"])
        assert dt.date() == freak.date

    def test_capture_datetime_failure_paths(self, freak):
        freak.date = datetime(2020, 1, 2).date()
        # struct.unpack('L', str) raises; the except handler then references an unbound variable
        with pytest.raises(UnboundLocalError):
            freak.getCaptureDateTime([0, "x"])

    @pytest.mark.xfail(strict=False, raises=AttributeError, reason="date.utcnow() does not exist (should be datetime)")
    def test_capture_datetime_no_date(self, freak, monkeypatch):
        class S:
            @staticmethod
            def unpack(f, d):
                return (12345678,)
        monkeypatch.setattr(fd, "struct", S)
        freak.date = None
        assert freak.getCaptureDateTime([0, "x"]) is not None

    @pytest.mark.xfail(strict=False, raises=(TypeError, struct.error),
                       reason="processLocationUpdate: native 'l' is 8 bytes, str input, datetime.date misuse")
    def test_process_location_update(self, freak):
        freak.processLocationUpdate(struct.pack("<llllL", 1, 2, 3, 4, 70111)[:16])

    def test_process_location_update_stubbed(self, freak, monkeypatch):
        vals = iter([-72, 43, 38, 70111])

        class S:
            @staticmethod
            def unpack(f, d):
                return (next(vals),)
        monkeypatch.setattr(fd, "struct", S)
        with pytest.raises(TypeError):     # datetime.date(...) called as a method with 3 args
            freak.processLocationUpdate("0123456789abcdef")
        assert (freak.lon, freak.lat, freak.alt) == (-72, 43, 38)

    # __serial_cmd -------------------------------------------------------------
    def test_serial_cmd_success(self, freak, capsys):
        freak.handle.rx = "junk&" + "&" + "C!N"
        assert freak._FREAKDUINO__serial_cmd("C!N") is True
        assert "Got a response" in capsys.readouterr().out

    def test_serial_cmd_bad_response_and_resend(self, freak, capsys):
        # leading junk forces the resend branch (>8 non-& chars) before the '&'
        freak.handle.rx = "x&" + "a" * 12 + "&" + "&" + "XYZ"
        assert freak._FREAKDUINO__serial_cmd("C!N", "5") is False
        out = capsys.readouterr().out
        assert "Invalid response" in out and "Resend" in out

    def test_serial_cmd_too_long(self, freak):
        with pytest.raises(Exception, match="minimum length"):
            freak._FREAKDUINO__serial_cmd("C!NX")


# ================================================================== Zigduino
class FakeAtmel:
    def __init__(self):
        self.calls = []
        self.rx = []
        self.rssi = -50
        self.serialclosed = False

    def serInit(self, port=None, **kw):
        self.calls.append(("serInit", port))

    def setup(self):
        self.calls.append(("setup",))

    def serClose(self):
        self.serialclosed = True

    def RF_setchannel(self, c):
        self.calls.append(("chan", c))

    def RF_autocrc(self, v):
        self.calls.append(("autocrc", v))

    def RF_txpacket(self, p):
        self.calls.append(("tx", p))

    def RF_rxpacket(self):
        return self.rx.pop(0) if self.rx else None

    def RF_getrssi(self):
        return self.rssi

    def poke(self, reg, val):
        self.calls.append(("poke", reg, val))
        return True


@pytest.fixture
def zig(monkeypatch):
    monkeypatch.setattr(zd, "GoodFETatmel128rfa1", FakeAtmel)
    monkeypatch.setattr(zd.time, "sleep", lambda s: None)
    return zd.ZIGDUINO("/dev/ttyUSB3")


class TestZigduino:
    def test_init_info_caps(self, zig):
        assert ("serInit", "/dev/ttyUSB3") in zig.handle.calls
        assert ("setup",) in zig.handle.calls
        assert zig.get_dev_info() == ["/dev/ttyUSB3", "Zigduino", ""]
        assert zig.check_capability(KBCapabilities.INJECT)
        assert zig.check_capability(KBCapabilities.SET_SYNC)
        assert not zig.check_capability(KBCapabilities.PHYJAM_REFLEX)
        assert zig.get_capabilities()[KBCapabilities.SNIFF]

    def test_close(self, zig):
        h = zig.handle
        zig.close()
        assert h.serialclosed and zig.handle is None

    def test_sniffer_on_off(self, zig):
        zig.sniffer_on()
        zig.sniffer_on(channel=15)
        assert ("chan", 15) in zig.handle.calls
        assert zig._channel == 15
        zig.sniffer_off()

    def test_set_channel(self, zig):
        zig.set_channel(26)
        assert zig._channel == 26
        zig.capabilities.setcapab(KBCapabilities.SETCHAN, False)
        with pytest.raises(Exception, match="does not support"):
            zig.set_channel(12)

    @pytest.mark.xfail(strict=False, reason="channel check uses 'or' (>=11 or <=26): invalid channel never rejected")
    def test_set_channel_invalid(self, zig):
        with pytest.raises(Exception, match="Invalid channel"):
            zig.set_channel(99)

    def test_inject_str(self, zig):
        zig.inject("ab", channel=12, count=2)
        assert zig.handle.calls.count(("tx", [4, ord("a"), ord("b")])) == 2
        assert ("autocrc", 1) in zig.handle.calls
        with pytest.raises(Exception, match="Empty"):
            zig.inject("")
        with pytest.raises(Exception, match="too long"):
            zig.inject("x" * 126)
        with pytest.raises(Exception, match="SubGHz"):
            zig.inject("ab", page=1)

    @pytest.mark.xfail(strict=False, raises=TypeError, reason="py3: inject() does ord(x) on ints from a bytes packet")
    def test_inject_bytes(self, zig):
        zig.inject(b"ab")

    def test_inject_requires_cap(self, zig):
        zig.capabilities.setcapab(KBCapabilities.INJECT, False)
        with pytest.raises(Exception, match="does not support"):
            zig.inject("ab")

    def test_pnext(self, zig):
        assert zig.pnext(timeout=500) is None
        from killerbee.kbutils import makeFCS
        body = b"\x41\x88\x07"
        good = body + makeFCS(body)
        zig.handle.rx.append(good)
        r = zig.pnext(timeout=10**7)
        assert r["validcrc"] is True and r["bytes"] == good
        assert r["rssi"] == -50 and r["dbm"] == -95 and r[2] == -50
        assert r["location"] is None and isinstance(r["datetime"], datetime)
        zig.handle.rx.append(body + b"\x00\x00")
        assert zig.pnext(timeout=10**7)["validcrc"] is False

    def test_jammer_ping(self, zig):
        with pytest.raises(Exception, match="Not yet"):
            zig.jammer_on()
        with pytest.raises(Exception, match="Not yet"):
            zig.jammer_off()

    def test_set_sync(self, zig):
        assert zig.set_sync() is True
        assert ("poke", zd.ATMEL_REG_SYNC, 0xA7) in zig.handle.calls
        with pytest.raises(Exception, match="1 byte"):
            zig.set_sync(0x1A7)
        with pytest.raises(Exception, match="nybble"):
            zig.set_sync(0xA0)
        zig.capabilities.setcapab(KBCapabilities.SET_SYNC, False)
        with pytest.raises(Exception, match="does not support"):
            zig.set_sync()
