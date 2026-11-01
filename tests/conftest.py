"""Shared pytest fixtures for the KillerBee test-suite.

Provides a fake GoodFET serial device (and, further below, fake USB helpers)
so that drivers can be exercised with no hardware attached.

If the environment variable APIMOTE_DEVSTRING is set, tests marked
``hardware`` run against the real device; otherwise they are skipped.
"""

import os
import struct

import pytest

BANNER = b"http://goodfet.sf.net/"


class FakeGoodFETSerial:
    """Minimal emulation of a pyserial port talking to GoodFET firmware.

    Understands the GoodFET framing (app, verb, count_lo, count_hi, data) and
    emulates enough of the CCSPI (CC2420) application for the Apimote driver:
    register peek/poke, strobes, packet rx/tx.
    """

    CCSPIAPP = 0x51
    last = None  # most recently created instance
    # Boards (os.environ["board"]) for which the fake answers the GoodFET
    # handshake.  Others (e.g. "telosb", "apimote1") see a silent port, as
    # with real hardware of the wrong type.  Tests may override this.
    accepted_boards = {None, "", "apimote2", "goodfet"}

    def __init__(self, port=None, baudrate=115200, *args, **kwargs):
        FakeGoodFETSerial.last = self
        self.port = port
        self.baudrate = baudrate
        self.timeout = kwargs.get("timeout")
        self.is_open = True
        self.rx = bytearray()
        self._tx = bytearray()
        self.regs = {}  # CC2420 register file
        self.strobes = []  # strobes received
        self.sent = []  # (app, verb, data) of every command
        self.tx_packets = []  # payloads passed to CCSPI/0x81
        self.rx_packets = []  # bytes objects returned by CCSPI/0x80
        self.rts = self.dtr = None
        if os.environ.get("board") in self.accepted_boards:
            self._queue_reply(0x00, 0x7F, BANNER)

    # ---- helpers for tests -------------------------------------------
    def queue_packet(self, data):
        """Make the next CCSPI rxpacket return ``data``."""
        self.rx_packets.append(bytes(data))

    def _queue_reply(self, app, verb, data=b""):
        self.rx += bytes([app, verb]) + struct.pack("<H", len(data)) + bytes(data)

    # ---- pyserial API --------------------------------------------------
    def write(self, data):
        self._tx += bytes(data)
        self._parse()
        return len(data)

    def read(self, n=1):
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def close(self):
        self.is_open = False

    def flushInput(self):
        pass

    def flushOutput(self):
        pass

    def reset_input_buffer(self):
        pass

    def reset_output_buffer(self):
        pass

    def setRTS(self, v):
        self.rts = v

    def setDTR(self, v):
        self.dtr = v

    def getCTS(self):
        return True

    def setBaudrate(self, b):
        self.baudrate = b

    # ---- protocol emulation ----------------------------------------------
    def _parse(self):
        while len(self._tx) >= 4:
            app, verb = self._tx[0], self._tx[1]
            count = self._tx[2] | (self._tx[3] << 8)
            if len(self._tx) < 4 + count:
                return
            data = bytes(self._tx[4 : 4 + count])
            del self._tx[: 4 + count]
            self.sent.append((app, verb, data))
            self._handle(app, verb, data)

    def _handle(self, app, verb, data):
        if app == 0x00 and verb == 0x81:  # monitor echo, as real firmware does
            self._queue_reply(app, verb, data)
            return
        if app != self.CCSPIAPP:
            self._queue_reply(app, verb, b"")
            return
        if verb == 0x00:  # trans / strobe
            self.strobes.append(data[0] if data else None)
            self._queue_reply(app, verb, bytes([0x40]))
        elif verb == 0x02:  # peek
            val = self.regs.get(data[0], 0)
            self._queue_reply(app, verb, bytes([data[0], (val >> 8) & 0xFF, val & 0xFF]))
        elif verb == 0x03:  # poke
            self.regs[data[0]] = (data[1] << 8) | data[2]
            self._queue_reply(app, verb, b"")
        elif verb == 0x80:  # rx packet
            pkt = self.rx_packets.pop(0) if self.rx_packets else b""
            self._queue_reply(app, verb, pkt)
        elif verb == 0x81:  # tx packet
            self.tx_packets.append(bytes(data))
            self._queue_reply(app, verb, b"")
        else:
            self._queue_reply(app, verb, b"")


@pytest.fixture
def fake_serial(monkeypatch):
    """Patch ``serial.Serial`` with FakeGoodFETSerial.

    Returns a list that collects every instance created (``fake_serial[-1]``
    is the most recent port).
    """
    import serial
    import time

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    instances = []

    def factory(*a, **kw):
        s = FakeGoodFETSerial(*a, **kw)
        instances.append(s)
        return s

    monkeypatch.setattr(serial, "Serial", factory)
    return instances


# ---------------------------------------------------------------------------
# Pure-python stand-in for the zigbee_crypt C extension (pycryptodome based).
# Lets tests of killerbee.scapy_extensions run without a compiled extension; it is
# cross-checked against the same known vectors as the real C extension in
# tests/test_zigbee_crypt.py.
# ---------------------------------------------------------------------------
class PyZigbeeCrypt:
    """Drop-in replacement for the zigbee_crypt module API."""

    @staticmethod
    def _ctr_stream(key, nonce, data, start=1):
        from Crypto.Cipher import AES

        block = bytes([1]) + nonce + start.to_bytes(2, "big")
        c = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=block)
        return c.encrypt(data)

    @classmethod
    def encrypt_ccm(cls, key, nonce, mic_len, payload, zigbee_data):
        from Crypto.Cipher import AES

        if mic_len == 0:
            return cls._ctr_stream(key, nonce, payload), b""
        c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mic_len)
        c.update(zigbee_data)
        return c.encrypt_and_digest(payload)

    @classmethod
    def decrypt_ccm(cls, key, nonce, mic, encrypted, zigbee_data):
        pt = cls._ctr_stream(key, nonce, encrypted)
        _enc, check = cls.encrypt_ccm(key, nonce, len(mic), pt, zigbee_data)
        return pt, 1 if check == mic else 0

    @staticmethod
    def _hash(data):
        from Crypto.Cipher import AES

        out = bytes(16)
        n = len(data)
        data = data + b"\x80"
        data += b"\x00" * ((-(len(data) + 2)) % 16) + (n * 8).to_bytes(2, "big")
        for i in range(0, len(data), 16):
            blk = data[i : i + 16]
            e = AES.new(out, AES.MODE_ECB).encrypt(blk)
            out = bytes(a ^ b for a, b in zip(e, blk))
        return out

    @classmethod
    def sec_key_hash(cls, key, inp):
        ipad = bytes(k ^ 0x36 for k in key)
        opad = bytes(k ^ 0x5C for k in key)
        return cls._hash(opad + cls._hash(ipad + inp))


@pytest.fixture
def py_zigbee_crypt(monkeypatch):
    """Make ``import zigbee_crypt`` return the pure-python substitute."""
    import sys

    monkeypatch.setitem(sys.modules, "zigbee_crypt", PyZigbeeCrypt)
    return PyZigbeeCrypt


FAKE_DEVSTRING = "/dev/ttyFAKE0"


@pytest.fixture
def apimote_env(monkeypatch):
    """Provide an Apimote device string.

    With APIMOTE_DEVSTRING set, real hardware is used and nothing is mocked.
    Otherwise serial.Serial is replaced by FakeGoodFETSerial and
    APIMOTE_DEVSTRING is set to a fake path for the duration of the test.
    Returns the device string.
    """
    real = os.environ.get("APIMOTE_DEVSTRING")
    if real:
        yield real
        return
    import serial
    import time

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setenv("APIMOTE_DEVSTRING", FAKE_DEVSTRING)
    instances = []

    def factory(*a, **kw):
        port = a[0] if a else kw.get("port")
        if port != FAKE_DEVSTRING:
            raise serial.serialutil.SerialException("could not open port %s: no such device" % port)
        s = FakeGoodFETSerial(*a, **kw)
        instances.append(s)
        return s

    monkeypatch.setattr(serial, "Serial", factory)

    import glob

    real_glob = glob.glob

    def fake_glob(pattern, *a, **kw):
        if pattern == "/dev/ttyUSB*":
            return [FAKE_DEVSTRING]
        return real_glob(pattern, *a, **kw)

    monkeypatch.setattr(glob, "glob", fake_glob)
    yield FAKE_DEVSTRING


def pytest_collection_modifyitems(config, items):
    if os.environ.get("APIMOTE_DEVSTRING"):
        return
    skip = pytest.mark.skip(reason="hardware test: set APIMOTE_DEVSTRING to run")
    for item in items:
        if "hardware" in item.keywords:
            item.add_marker(skip)
