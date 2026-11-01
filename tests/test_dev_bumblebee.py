import pytest
import usb.core
import usb.util

from killerbee import dev_bumblebee as bb
from killerbee.dev_bumblebee import Bumblebee, CommProtocolPacket
from killerbee.kbutils import KBCapabilities


def crc(b):
    c = 0xFF
    for i in b:
        c ^= i
    return c


def msg(cmd, data=b""):
    buf = bytes([len(data) + 3, cmd]) + data
    return buf + bytes([crc(buf)])


class FakeDev:
    iProduct = 1

    def __init__(self):
        self.inq = []      # chunks returned by read
        self.written = []
        self.auto_ack = True

    def set_configuration(self):
        pass

    def write(self, ep, data):
        self.written.append((ep, bytes(data)))
        if self.auto_ack and len(data) >= 2 and ep == Bumblebee.EP_OUT:
            self.inq.append(msg(data[1] + 1))
        return len(data)

    def read(self, ep, buf, timeout):
        if not self.inq:
            raise usb.core.USBError("t", errno=110)
        c = self.inq.pop(0)
        if isinstance(c, Exception):
            raise c
        buf[:len(c)] = type(buf)("B", c)
        return len(c)


@pytest.fixture(autouse=True)
def p(monkeypatch):
    monkeypatch.setattr(usb.util, "get_string", lambda d, i: "Bumblebee")
    monkeypatch.setattr(bb.time, "sleep", lambda s: None)


def mk():
    dev = FakeDev()
    return Bumblebee(dev, None), dev


def test_basic():
    d, _ = mk()
    assert d.get_dev_info() == ["Bumblebee", "BUMBLEBEE", ""]
    assert d.check_capability(KBCapabilities.INJECT)
    assert d.get_capabilities()
    pk = CommProtocolPacket(1, b"x")
    assert pk.get_command() == 1 and pk.get_data() == b"x"
    for f in (d.jammer_on, d.set_sync, d.jammer_off):
        with pytest.raises(Exception, match="Not yet"):
            f()


def test_sniffer_inject_close():
    d, dev = mk()
    d.sniffer_on(channel=12)
    d.inject(b"\x01\x02", channel=13, count=2)
    d.close()
    with pytest.raises(Exception, match="SubGHz"):
        d.set_channel(12, 1)
    assert any(w[1][1] == Bumblebee.CMD_SNIFF_OFF for w in dev.written)
    d.close()
    with pytest.raises(Exception, match="Empty"):
        d.inject(b"")
    with pytest.raises(Exception, match="too long"):
        d.inject(b"a" * 126)


def test_no_device():
    d, _ = mk()
    d.dev = None
    with pytest.raises(Exception, match="not connected"):
        d.sniffer_on()
    with pytest.raises(Exception, match="not connected"):
        d.sniffer_off()
    d.set_channel(12)
    assert d._channel == 12


def test_send_message_multiblock_and_ack_timeout(monkeypatch):
    d, dev = mk()
    dev.auto_ack = False
    n = d.send_message(Bumblebee.CMD_SEND_PKT, b"a" * 100)
    assert n == 103 and len(dev.written) == 2
    ticks = iter(range(0, 1000))
    monkeypatch.setattr(bb.time, "time", lambda: next(ticks))
    assert d.wait_for_ack(Bumblebee.CMD_INIT_ACK) is False
    # exactly one 64-byte block
    d.send_message(Bumblebee.CMD_SEND_PKT, b"a" * 61)
    assert len(dev.written) == 3


def test_process_packet_badcrc_and_process_rx_errors():
    d, dev = mk()
    good = msg(Bumblebee.CMD_GOT_PKT, b"zz")
    bad = bytearray(msg(5, b"q")); bad[-1] ^= 1
    d.rx_buffer = bytes(bad) + good
    pk = list(d.process_packet())
    assert len(pk) == 1 and pk[0].get_data() == b"zz"
    dev.inq = [usb.core.USBError("t", errno=60)]
    assert d.process_rx() is None
    dev.inq = [usb.core.USBError("x", errno=5)]
    with pytest.raises(usb.core.USBError):
        d.process_rx()


def test_pnext():
    d, dev = mk()
    dev.auto_ack = False
    dev.inq = [msg(Bumblebee.CMD_SNIFF_ON_ACK)]
    # first pnext starts sniffer; no packet queued -> None
    assert d.pnext() is None
    dev.inq = [msg(Bumblebee.CMD_GOT_PKT, bytes([0xF0, 0x05]) + b"\x01\x02\x03")]
    r = d.pnext()
    assert r["rssi"] == -16 and r["lqi"] == 5 and r["validcrc"]
    assert r[0].startswith(b"\x01\x02\x03") and len(r[0]) == 5
    assert r["bytes"] == r[0]


@pytest.mark.parametrize("chan", [0, 10, 27, 100])
def test_set_channel_invalid(chan):
    d, _ = mk()
    with pytest.raises(Exception, match="Invalid channel"):
        d.set_channel(chan)
