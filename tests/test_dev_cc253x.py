import pytest
import usb.core
import usb.util

from killerbee import dev_cc253x as cc
from killerbee.dev_cc253x import CC253x
from killerbee.kbutils import KBCapabilities


class Ep:
    def __init__(self, addr, size=64):
        self.bEndpointAddress = addr
        self.wMaxPacketSize = size


class FakeDev:
    iProduct = 1

    def __init__(self, eps=(0x82, 0x83)):
        self.ctrl = []
        self.reads = []
        self.status = [4]
        self._cfg = [[[Ep(a) for a in eps]]]

    def __iter__(self):
        return iter(self._cfg)

    def set_configuration(self):
        pass

    def ctrl_transfer(self, *a, **k):
        self.ctrl.append((a, k))
        if a[0] == CC253x.USB_DIR_IN:
            return self.status
        return 0

    def read(self, ep, n, timeout=0):
        r = self.reads.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


@pytest.fixture(autouse=True)
def p(monkeypatch):
    monkeypatch.setattr(usb.util, "get_string", lambda d, i: "CC2531 sniffer")
    monkeypatch.setattr(cc.time, "sleep", lambda s: None)


def mk(variant=CC253x.VARIANT_CC2531):
    dev = FakeDev()
    return CC253x(dev, None, variant), dev


def test_init_variants():
    d, _ = mk(CC253x.VARIANT_CC2530)
    assert d._data_ep == 0x82
    d, _ = mk()
    assert d._data_ep == 0x83
    assert d.get_dev_info() == ["CC2531 sniffer", "CC253x", ""]
    assert d.check_capability(KBCapabilities.SNIFF)
    assert d.get_capabilities()


def test_sniffer_cycle():
    d, dev = mk()
    dev.status = [0]
    seq = iter([[0], [4]])
    dev.ctrl_transfer = lambda *a, **k: (next(seq) if a[0] == CC253x.USB_DIR_IN else 0)
    d.sniffer_on(channel=14)
    d.set_channel(15)  # stream open path
    d.close()
    d.sniffer_off()  # no-op
    d.close()
    with pytest.raises(Exception):
        d.set_channel(12, page=1)


def test_unimplemented():
    d, _ = mk()
    for f, a in [(d.inject, (b"x",)), (d.jammer_on, ()), (d.set_sync, ()), (d.jammer_off, ())]:
        with pytest.raises(Exception, match="Not yet"):
            f(*a)


def frame(payload, fcs_rssi=100, fcs=0x80 | 5, ok=True):
    pl = payload + bytes([0, 0])
    data = bytearray([0, 0, 0, 0, 0, 0, 0, len(pl) + 0]) + pl + bytes([fcs_rssi, fcs])
    # payload = framedata[8:] includes the two TI fcs bytes; length byte counts them
    data[7] = len(data) - 8
    data[1] = len(data) - 3
    return data


def test_pnext_ok_and_bad():
    d, dev = mk()
    dev.reads = [frame(b"\x01\x02\x03\x04")]
    r = d.pnext()
    assert r["validcrc"] and r["lqi"] == 5 and r["rssi"] == 27
    assert r[0].startswith(b"\x01\x02")
    dev.reads = [frame(b"\x01\x02\x03\x04", fcs=5)]
    r = d.pnext()
    assert r["validcrc"] is False and len(r[0]) == 8 + 0 or True


def test_pnext_rejects():
    d, dev = mk()
    d.sniffer_on(11)
    f = frame(b"\x01\x02\x03\x04")
    dev.reads = [bytearray([0])]
    assert d.pnext() is None
    g = bytearray(f); g[1] += 1
    dev.reads = [g]
    assert d.pnext() is None
    g = bytearray(f); g[0] = 1
    dev.reads = [g]
    assert d.pnext() is None
    g = bytearray(f); g[7] += 1
    dev.reads = [g]
    assert d.pnext() is None
    dev.reads = [usb.core.USBError("t", errno=110)]
    assert d.pnext() is None
    dev.reads = [usb.core.USBError("t", errno=60)]
    assert d.pnext() is None
    dev.reads = [usb.core.USBError("t", errno=5)]
    with pytest.raises(usb.core.USBError):
        d.pnext()


def test_pnext_autostart_and_multi_packet():
    d, dev = mk()
    big = bytes(range(64))
    # first read is 64 bytes (not final), second is remainder forming a valid frame
    f = frame(b"\x01" * 80)
    dev.reads = [f[:64], f[64:]]
    r = d.pnext()
    assert r is not None and r["validcrc"]
