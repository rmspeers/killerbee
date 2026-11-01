import pytest
import usb.core
import usb.util

from killerbee import dev_rzusbstick as rz
from killerbee.dev_rzusbstick import RZUSBSTICK
from killerbee.kbutils import KBCapabilities

OK = [rz.RZ_RESP_SUCCESS]


class FakeDev:
    def __init__(self, reads=None, fail_setup=False):
        self.bus = 1
        self.address = 2
        self.iProduct = 1
        self.iSerialNumber = 2
        self.bMaxPacketSize0 = 64
        self.reads = list(reads or [])
        self.resp = []
        self.writes = []
        self.fail_setup = fail_setup
        self.write_ret = None
        self.write_exc = None
        self.read_exc = None

    def set_configuration(self):
        if self.fail_setup:
            raise usb.core.USBError("x")

    def reset(self):
        pass

    def write(self, ep, data):
        if self.write_exc:
            raise self.write_exc
        self.writes.append((ep, bytes(data)))
        return len(data) if self.write_ret is None else self.write_ret

    def read(self, ep, n, timeout=0):
        if self.read_exc:
            raise self.read_exc
        if ep == rz.RZ_USB_RESPONSE_EP:
            if not self.resp:
                return [rz.RZ_RESP_SUCCESS]
            return self.resp.pop(0)
        r = self.reads.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def make(prod="KILLERB006", dev=None, monkeypatch=None):
    dev = dev or FakeDev()
    strs = {1: prod, 2: "SER"}
    usb.util.get_string = lambda d, i: strs[i]
    usb.util.release_interface = lambda d, i: None
    return RZUSBSTICK(dev, None), dev


@pytest.fixture(autouse=True)
def patch_usb(monkeypatch):
    monkeypatch.setattr(usb.util, "get_string", lambda d, i: {1: "KILLERB006", 2: "SER"}[i])
    monkeypatch.setattr(usb.util, "release_interface", lambda d, i: None)
    monkeypatch.setattr(rz.time, "sleep", lambda s: None)


def mk(prod="KILLERB006", **kw):
    dev = FakeDev(**kw)
    strs = {1: prod, 2: "SER"}
    usb.util.get_string = lambda d, i: strs[i]
    return RZUSBSTICK(dev, None), dev


def test_init_errors():
    with pytest.raises(Exception, match="No interface"):
        RZUSBSTICK(None, None)
    with pytest.raises(Exception, match="Unable to open"):
        RZUSBSTICK(FakeDev(fail_setup=True), None)


@pytest.mark.parametrize("prod,caps", [
    ("RZUSBSTICK", [KBCapabilities.BOOT, KBCapabilities.SNIFF]),
    ("KILLERB001", [KBCapabilities.INJECT]),
    ("KILLERB006", [KBCapabilities.INJECT, KBCapabilities.BOOT]),
    ("KILLERB00T", [KBCapabilities.BOOT]),
    ("OTHER", []),
])
def test_capabilities(prod, caps):
    d, _ = mk(prod)
    for c in caps:
        assert d.check_capability(c)
    assert d.get_capabilities()
    assert d.get_dev_info() == ["1:2", prod, "SER"]


def test_del_and_close():
    d, _ = mk()
    d.close()
    d.__del__()
    d.close = lambda: (_ for _ in ()).throw(RuntimeError())
    d.__del__()


def test_write_errors():
    d, dev = mk()
    dev.write_ret = 0
    with pytest.raises(Exception, match="Issue writing"):
        d._set_mode()
    dev.write_ret = None
    dev.write_exc = usb.core.USBError("t", errno=110)
    d._set_mode()  # timeout then read OK
    dev.write_exc = usb.core.USBError("bad", errno=5)
    with pytest.raises(usb.core.USBError):
        d._set_mode()
    dev.write_exc = None
    dev.resp = [[rz.RZ_RESP_HW_TIMEOUT]]
    with pytest.raises(Exception, match="Hardware Timeout"):
        d._set_mode()
    dev.resp = [[0xEE]]
    with pytest.raises(Exception, match="Unknown USB write"):
        d._set_mode()


def test_read_errors():
    d, dev = mk()
    dev.read_exc = usb.core.USBError("t", errno=110)
    with pytest.raises(Exception, match="No response"):  # read timed out
        d._set_mode()
    dev.read_exc = usb.core.USBError("bad", errno=5)
    with pytest.raises(usb.core.USBError):
        d._set_mode()


def test_sniffer_and_channel():
    d, dev = mk()
    d.sniffer_on(channel=15)
    assert (rz.RZ_USB_COMMAND_EP, bytes([rz.RZ_CMD_SET_CHANNEL, 15])) in dev.writes
    d.sniffer_off()
    with pytest.raises(Exception, match="Invalid channel"):
        d.set_channel(5, 0)
    with pytest.raises(Exception, match="SubGHz"):
        d.set_channel(12, 1)


def test_jammer_and_boot():
    d, dev = mk()
    with pytest.raises(Exception):
        d.jammer_on(15)  # PHYJAM False
    with pytest.raises(Exception):
        d.jammer_off()
    d.capabilities.setcapab(KBCapabilities.PHYJAM, True)
    d.jammer_on(channel=12)
    d.jammer_off()
    d.enter_bootloader()
    dev.resp = [[rz.RZ_RESP_BOOT_PARAM, 1, 2]]
    assert list(d.get_bootloader_version()) == [1, 2]
    dev.resp = [[rz.RZ_RESP_BOOT_PARAM, 1, 2, 3]]
    assert list(d.get_bootloader_signature()) == [1, 2, 3]
    dev.resp = [[rz.RZ_RESP_SIGN_ON, 1, 65]]
    d.bootloader_sign_on()
    d.bootloader_start_application()


def test_inject():
    d, dev = mk()
    d.inject(b"\x01\x02", channel=12, count=2)
    inj = [w for w in dev.writes if w[1][0] == rz.RZ_CMD_INJECT_FRAME]
    assert len(inj) == 2 and inj[0][1] == bytes([rz.RZ_CMD_INJECT_FRAME, 4, 1, 2, 0, 0])
    with pytest.raises(Exception, match="Empty"):
        d.inject(b"")
    with pytest.raises(Exception, match="too long"):
        d.inject(b"a" * 126)
    d2, _ = mk("RZUSBSTICK")
    with pytest.raises(Exception):
        d2.inject(b"a")


def test_ping():
    d, _ = mk()
    with pytest.raises(Exception, match="Not yet"):
        d.ping(1, 2, 3)


def ac_pkt(payload_with_lqi, crc=1, rssi=40, total=None):
    n = len(payload_with_lqi)
    hdr = [rz.RZ_EVENT_STREAM_AC_DATA, 9 + n, 0, 0, 0, 0, rssi, crc, 0]
    pkt = hdr + list(payload_with_lqi)
    pkt[1] = len(pkt)
    return pkt


def test_pnext_single():
    d, dev = mk()
    dev.reads = [ac_pkt(b"\xaa\xbb\x77")]
    r = d.pnext()
    assert r[0] == b"\xaa\xbb" and r["lqi"] == 0x77 and r["validcrc"] and r["rssi"] == 40
    # stream now open; bad CRC
    dev.reads = [ac_pkt(b"\xaa\x01", crc=0)]
    assert d.pnext()["validcrc"] is False


def test_pnext_multi():
    d, dev = mk()
    first = ac_pkt(b"\x01\x02\x03")
    first[1] = len(first) + 2  # expect 2 more bytes
    dev.reads = [first, [0x01, 0x09]]
    r = d.pnext()
    assert r[0] == b"\x01\x02\x03\x01"
    assert r["lqi"] == 9


def test_pnext_none_cases():
    d, dev = mk()
    dev.reads = [[]]
    assert d.pnext() is None
    dev.reads = [[0x99, 1]]
    assert d.pnext() is None
    dev.reads = [usb.core.USBError("t", errno=110)]
    assert d.pnext() is None
    dev.reads = [usb.core.USBError("x", errno=60)]
    assert d.pnext() is None  # args[0] == 60 is tolerated
    dev.reads = [usb.core.USBError("bad", errno=5)]
    with pytest.raises(usb.core.USBError):
        d.pnext()
    first = ac_pkt(b"\x01\x02\x03")
    first[1] = len(first) + 5
    dev.reads = [first, [0x99]]
    # continuation, not complete, then empty -> None
    dev.reads = [first, []]
    assert d.pnext() is None
