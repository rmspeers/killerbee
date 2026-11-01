import unittest
import struct
import argparse
import os

from killerbee.kbutils import * 

import pytest

@pytest.mark.usefixtures("apimote_env")
class TestKbutils(unittest.TestCase):
    def test_kbcapabilities_init(self):
        kbc=KBCapabilities()
    
        self.assertFalse(kbc._capabilities[KBCapabilities.NONE])
        self.assertFalse(kbc._capabilities[KBCapabilities.SNIFF])
        self.assertFalse(kbc._capabilities[KBCapabilities.SETCHAN])
        self.assertFalse(kbc._capabilities[KBCapabilities.INJECT])
        self.assertFalse(kbc._capabilities[KBCapabilities.PHYJAM])
        self.assertFalse(kbc._capabilities[KBCapabilities.SELFACK])
        self.assertFalse(kbc._capabilities[KBCapabilities.PHYJAM_REFLEX])
        self.assertFalse(kbc._capabilities[KBCapabilities.SET_SYNC])
        self.assertFalse(kbc._capabilities[KBCapabilities.FREQ_2400])
        self.assertFalse(kbc._capabilities[KBCapabilities.FREQ_900])
        self.assertFalse(kbc._capabilities[KBCapabilities.FREQ_863])
        self.assertFalse(kbc._capabilities[KBCapabilities.FREQ_868])
        self.assertFalse(kbc._capabilities[KBCapabilities.FREQ_870])
        self.assertFalse(kbc._capabilities[KBCapabilities.FREQ_915])
        self.assertFalse(kbc._capabilities[KBCapabilities.BOOT])

    def test_kbcapabilities_check(self):
        kbc=KBCapabilities()
    
        self.assertFalse(kbc.check(KBCapabilities.NONE))
        self.assertFalse(kbc.check(KBCapabilities.SNIFF))
        self.assertFalse(kbc.check(KBCapabilities.SETCHAN))
        self.assertFalse(kbc.check(KBCapabilities.INJECT))
        self.assertFalse(kbc.check(KBCapabilities.PHYJAM))
        self.assertFalse(kbc.check(KBCapabilities.SELFACK))
        self.assertFalse(kbc.check(KBCapabilities.PHYJAM_REFLEX))
        self.assertFalse(kbc.check(KBCapabilities.SET_SYNC))
        self.assertFalse(kbc.check(KBCapabilities.FREQ_2400))
        self.assertFalse(kbc.check(KBCapabilities.FREQ_900))
        self.assertFalse(kbc.check(KBCapabilities.FREQ_863))
        self.assertFalse(kbc.check(KBCapabilities.FREQ_868))
        self.assertFalse(kbc.check(KBCapabilities.FREQ_870))
        self.assertFalse(kbc.check(KBCapabilities.FREQ_915))
        self.assertFalse(kbc.check(KBCapabilities.BOOT))

    def test_kbcapabilities_getlist(self):
        kbc=KBCapabilities()
        capabilities = kbc.getlist()
    
        self.assertFalse(capabilities[KBCapabilities.NONE])
        self.assertFalse(capabilities[KBCapabilities.SNIFF])
        self.assertFalse(capabilities[KBCapabilities.SETCHAN])
        self.assertFalse(capabilities[KBCapabilities.INJECT])
        self.assertFalse(capabilities[KBCapabilities.PHYJAM])
        self.assertFalse(capabilities[KBCapabilities.SELFACK])
        self.assertFalse(capabilities[KBCapabilities.PHYJAM_REFLEX])
        self.assertFalse(capabilities[KBCapabilities.SET_SYNC])
        self.assertFalse(capabilities[KBCapabilities.FREQ_2400])
        self.assertFalse(capabilities[KBCapabilities.FREQ_900])
        self.assertFalse(capabilities[KBCapabilities.FREQ_863])
        self.assertFalse(capabilities[KBCapabilities.FREQ_868])
        self.assertFalse(capabilities[KBCapabilities.FREQ_870])
        self.assertFalse(capabilities[KBCapabilities.FREQ_915])
        self.assertFalse(capabilities[KBCapabilities.BOOT])

    def test_kbcapabilities_setcapab(self): 
        kbc=KBCapabilities()
      
        self.assertFalse(kbc.check(KBCapabilities.NONE))

        kbc.setcapab(KBCapabilities.NONE, True)

        self.assertTrue(kbc.check(KBCapabilities.NONE))

    def test_kbcapabilities_require(self):
        kbc=KBCapabilities()

        self.assertRaises(Exception, kbc.require, KBCapabilities.NONE)

    def test_kbcapabilities_is_valid_channel(self):
        kbc=KBCapabilities()
        
        #Check FREQ_863
        kbc.setcapab(KBCapabilities.FREQ_863, True)
        self.assertFalse(kbc.is_valid_channel(27, 28))
        self.assertTrue(kbc.is_valid_channel(26, 28))
        kbc.setcapab(KBCapabilities.FREQ_863, False)
        self.assertFalse(kbc.is_valid_channel(26, 28))

        #Check FREQ_868
        kbc.setcapab(KBCapabilities.FREQ_868, True)
        self.assertFalse(kbc.is_valid_channel(9, 29))
        self.assertTrue(kbc.is_valid_channel(8, 29))
        kbc.setcapab(KBCapabilities.FREQ_868, False)
        self.assertFalse(kbc.is_valid_channel(8, 29))

        #Check FREQ_870
        kbc.setcapab(KBCapabilities.FREQ_870, True)
        self.assertFalse(kbc.is_valid_channel(27, 30))
        self.assertTrue(kbc.is_valid_channel(26, 30))
        kbc.setcapab(KBCapabilities.FREQ_870, False)
        self.assertFalse(kbc.is_valid_channel(26, 30))

        #Check FREQ_915
        kbc.setcapab(KBCapabilities.FREQ_915, True)
        self.assertFalse(kbc.is_valid_channel(27, 31))
        self.assertTrue(kbc.is_valid_channel(26, 31))
        kbc.setcapab(KBCapabilities.FREQ_915, False)
        self.assertFalse(kbc.is_valid_channel(26, 31))

        kbc.setcapab(KBCapabilities.FREQ_863, True)
        kbc.setcapab(KBCapabilities.FREQ_868, True)
        kbc.setcapab(KBCapabilities.FREQ_870, True)
        kbc.setcapab(KBCapabilities.FREQ_915, True)
        self.assertFalse(kbc.is_valid_channel(1, 27))
        self.assertFalse(kbc.is_valid_channel(1, 32))
        kbc.setcapab(KBCapabilities.FREQ_863, False)
        kbc.setcapab(KBCapabilities.FREQ_868, False)
        kbc.setcapab(KBCapabilities.FREQ_870, False)
        kbc.setcapab(KBCapabilities.FREQ_915, False)

        #Check FREQ_2400
        kbc.setcapab(KBCapabilities.FREQ_2400, True)
        self.assertTrue(kbc.is_valid_channel(11))
        self.assertFalse(kbc.is_valid_channel(10))
        self.assertFalse(kbc.is_valid_channel(27))
        kbc.setcapab(KBCapabilities.FREQ_2400, False)

        #Check FREQ_900
        kbc.setcapab(KBCapabilities.FREQ_900, True)
        self.assertTrue(kbc.is_valid_channel(1))
        self.assertFalse(kbc.is_valid_channel(11))
        self.assertFalse(kbc.is_valid_channel(0))
        kbc.setcapab(KBCapabilities.FREQ_900, False)

    def test_kbcapabilities_frequency(self):
        kbc=KBCapabilities()
      
        #Check FREQ_2400
        kbc.setcapab(KBCapabilities.FREQ_2400, True)
        self.assertEqual(0, kbc.frequency(11, 1))
        self.assertEqual(0, kbc.frequency(10))
        kbc.setcapab(KBCapabilities.FREQ_900, True)
        self.assertEqual(0, kbc.frequency(1))   # FREQ_900 frequencies not yet implemented
        kbc.setcapab(KBCapabilities.FREQ_900, False)
        self.assertEqual(0, kbc.frequency(27))
        self.assertEqual(2405000, kbc.frequency(11))
        self.assertEqual(2480000, kbc.frequency(26))
        kbc.setcapab(KBCapabilities.FREQ_2400, False)

        #Check FREQ_900 NOT SUPPORTED
        #kbc.setcapab(KBCapabilities.FREQ_900, True)
        #self.assertEqual(0, kbc.frequency(1))

        #Check FREQ_863
        kbc.setcapab(KBCapabilities.FREQ_863, True)
        self.assertEqual(0, kbc.frequency(27, 28))
        self.assertEqual(863250, kbc.frequency(0, 28))
        self.assertEqual(868450, kbc.frequency(26, 28))
        kbc.setcapab(KBCapabilities.FREQ_863, False)

        #Check FREQ_868
        kbc.setcapab(KBCapabilities.FREQ_868, True)
        self.assertEqual(0, kbc.frequency(9, 29))
        self.assertEqual(868650, kbc.frequency(0, 29))
        self.assertEqual(870250, kbc.frequency(8, 29))
        kbc.setcapab(KBCapabilities.FREQ_868, False)

        #Check FREQ_870
        kbc.setcapab(KBCapabilities.FREQ_870, True)
        self.assertEqual(0, kbc.frequency(27, 30))
        self.assertEqual(870250, kbc.frequency(0, 30))
        self.assertEqual(875450, kbc.frequency(26, 30))
        kbc.setcapab(KBCapabilities.FREQ_870, False)

        #Check FREQ_915
        kbc.setcapab(KBCapabilities.FREQ_915, True)
        self.assertEqual(0, kbc.frequency(27, 31))
        self.assertEqual(915350, kbc.frequency(0, 31))
        self.assertEqual(920550, kbc.frequency(26, 31))
        kbc.setcapab(KBCapabilities.FREQ_915, False)

    def test_findFromList_init(self):
        ffl = findFromList(['vendor0', 'vendor1'], ['product0', 'product1'])

        self.assertEqual('vendor0', ffl._vendors[0])
        self.assertEqual('vendor1', ffl._vendors[1])
        self.assertEqual('product0', ffl._products[0])
        self.assertEqual('product1', ffl._products[1])

    #TODO device is pyusb object 
    def _test_findFromList_call(self):
        ffl = findFromList(['vendor0', 'vendor1'], ['product0', 'product1'])

        device = {
            'idVendor': 'vendor0',
            'idProduct': 'product1' 
        }

        self.assertTrue(ffl(device))

        device = {
            'idVendor': 'vendor3',
            'idProduct': 'product3' 
        }

        self.assertFalse(ffl(device))

    def test_findFromListAndBusDevId_init(self):
        busnum = 1
        devnum = 1
        vendors = ['vendor0', 'vendor1']
        products = ['product0', 'product1']
        fflabdi = findFromListAndBusDevId(busnum, devnum, vendors, products)

        self.assertEqual(1, fflabdi._busNum)
        self.assertEqual(1, fflabdi._devNum)

    #TODO device is pyusb object 
    def _test_findFromListAndBusDevId_call(self):
        busnum = 1
        devnum = 1
        vendors = ['vendor0', 'vendor1']
        products = ['product0', 'product1']
        fflabdi = findFromListAndBusDevId(busnum, devnum, vendors, products)

        device = {
            'idVendor': 'vendor0',
            'idProduct': 'product1',
            'bus': 1,
            'address': 1
        }

        self.assertTrue(fflabdi(device))

        device = {
            'idVendor': 'vendor0',
            'idProduct': 'product1',
            'bus': 2,
            'address': 2
        }

        self.assertFalse(fflabdi(device))

    #TODO && deprecate usb v0x
    def _test_devlist_usb_v1x(self):
        self.assertTrue(True)
    def _test_devlist_usb_v0x(self):
        self.assertTrue(True)    

    def test_devlist(self):
        devlist()

        self.assertTrue(True)

    #TODO Remove this empty function
    def _test_get_serial_devs(self):
        self.assertTrue(True)

    #TODO lots of false positives
    def test_getSerialDeviceString(self):
        path = "/ttyUSB0"
        self.assertTrue(isSerialDeviceString(path))
        path = "/dev/ttyUSB0"
        self.assertTrue(isSerialDeviceString(path))
        path = "/////dev//////ttyUSB0"
        self.assertTrue(isSerialDeviceString(path))
        path = "/ttpUSB0"
        self.assertTrue(isSerialDeviceString(path))
        path = "/"
        self.assertTrue(isSerialDeviceString(path))
        path = "tty"
        self.assertTrue(isSerialDeviceString(path))
        path = "kitty"
        self.assertTrue(isSerialDeviceString(path))
        path = "test"
        self.assertFalse(isSerialDeviceString(path))

    def test_get_serial_ports(self):
        self.assertTrue(os.environ['APIMOTE_DEVSTRING'] in get_serial_ports())

    def test_isIpAddr(self):
        self.assertFalse(isIpAddr("256.256.256.256"))
        self.assertFalse(isIpAddr("1.1.1.1.1"))
        self.assertFalse(isIpAddr("1.1.1"))
        self.assertFalse(isIpAddr("not an ip address"))
        self.assertTrue(isIpAddr("1.1.1.1"))
        self.assertTrue(isIpAddr("255.255.255.255"))

        self.assertTrue(isIpAddr("2607::4"))
        self.assertTrue(isIpAddr("2607:f0d0:1002:51::4"))
        self.assertTrue(isIpAddr("2607:f0d0:1002:0051:0000:0000:0000:0004"))
        self.assertFalse(isIpAddr("gggg:gggg:gggg:gggg:gggg:gggg:gggg:gggg:gggg"))

    #TAKE A LONG TIME TO RUN DURING DEVELOPMENT
    def _test_isgoodfetccspi(self):
        self.assertTrue(isgoodfetccspi(os.environ['APIMOTE_DEVSTRING']))

    def _test_iszigduino(self):
        self.assertFalse(iszigduino(os.environ['APIMOTE_DEVSTRING']))

    def _test_issl_nodetest(self):
        self.assertFalse(issl_nodetest(os.environ['APIMOTE_DEVSTRING']))

    def _test_issl_beehive(self):
        self.assertFalse(issl_beehive(os.environ['APIMOTE_DEVSTRING']))

    def _test_isfreakduino(self):
        self.assertFalse(isfreakduino(os.environ['APIMOTE_DEVSTRING']))

    def test_search_usb(self):
        device = "123"
        self.assertRaises(KBInterfaceError, search_usb, device)

        device = "1:2:3"
        self.assertRaises(ValueError, search_usb, device)

        device = "a:b"
        self.assertRaises(ValueError, search_usb, device)

        device = ":"
        self.assertRaises(ValueError, search_usb, device)

        device = "1:2"
        search_usb(device)

    #TODO Deprecate usb v0x
    def _test_search_usb_bus_v0x(self):
        self.assertTrue(True)
    
    def test_hexdump(self):
        expected = "0000:  74 65 73 74" + " " * 39 + "test\n"
        self.assertEqual(expected, hexdump(b"test"))
        self.assertEqual(expected, hexdump("test"))
        self.assertEqual(expected, hexdump(bytearray(b"test")))
        self.assertEqual("", hexdump(b""))
        dump = hexdump(bytes(range(0x7e, 0x7e + 20)), length=8)
        lines = dump.splitlines()
        self.assertEqual(3, len(lines))
        self.assertEqual("0000:  7e 7f 80 81 82 83 84 85   ~.......", lines[0])
        self.assertTrue(lines[2].startswith("0010:  8e 8f 90 91"))

    def test_randbytes(self):
        self.assertEqual(1, len(randbytes(1)))
        self.assertEqual(4, len(randbytes(4)))
        self.assertEqual(100, len(randbytes(100)))
        self.assertEqual(1000, len(randbytes(1000)))

    def test_randbytes_type(self):
        self.assertIsInstance(randbytes(4), bytes)

    def test_randmac(self):
        self.assertEqual(8, len(randmac()))
        self.assertEqual(3, len(randmac(3)))
        mac = randmac()
        self.assertIsInstance(mac, bytes)
        # air-format (LSB first): OUI ends up at the end of the byte string, reversed
        self.assertIn(mac[-3:][::-1], (b"\x00\x0d\x6f", b"\x00\x12\x4b", b"\x00\x04\xa3", b"\x00\x04\x25",
            b"\x00\x11\x7d", b"\x00\x13\xa2", b"\x00\x30\x66", b"\x00\x0b\x57", b"\x00\x04\x9f",
            b"\x00\x21\xed", b"\x00\xa0\x50"))

    def test_makeFCS(self):
        data = b'\x01' * 20
        self.assertEqual(b'\xa7\xf7', makeFCS(data))
        data = b'\x02' * 20
        self.assertEqual(b'\x5f\xe7', makeFCS(data))

    def test_bytearray_to_bytes(self):
        b = bytes([0x01, 0x02, 0x03, 0x04])
        self.assertEqual(b, bytearray_to_bytes(b))
        



# ---------------------------------------------------------------------------
# Additional mock-driven tests (no hardware)
# ---------------------------------------------------------------------------
import killerbee.kbutils as kbu
import serial as _serial
import usb.core


class ScriptSerial:
    """Scripted serial port for the text-based device probes."""
    def __init__(self, lines=(), reads=b"", **kw):
        self.lines = list(lines)
        self.reads = bytearray(reads)
        self.written = []
        self.in_waiting = 0
        self.closed = False

    def write(self, d):
        self.written.append(d)

    def readline(self):
        return self.lines.pop(0) if self.lines else b""

    def read(self, n=1):
        out = bytes(self.reads[:n])
        del self.reads[:n]
        return out

    def close(self):
        self.closed = True


class FakeUsbDev:
    def __init__(self, vid, pid, bus=1, address=2):
        self.idVendor, self.idProduct, self.bus, self.address = vid, pid, bus, address
        self.iProduct, self.iSerialNumber = 1, 2


@pytest.fixture
def clean_board(monkeypatch):
    monkeypatch.delenv("board", raising=False)
    monkeypatch.delenv("platform", raising=False)


def test_find_from_list_call():
    ffl = findFromList([1, 2], [10, 20])
    assert ffl(FakeUsbDev(1, 10))
    assert not ffl(FakeUsbDev(3, 10))
    assert not ffl(FakeUsbDev(1, 30))


def test_find_from_list_and_bus_dev_id_call():
    f = findFromListAndBusDevId(1, 2, [1], [10])
    assert f(FakeUsbDev(1, 10, bus=1, address=2))
    assert not f(FakeUsbDev(1, 10, bus=2, address=2))
    assert not f(FakeUsbDev(1, 10, bus=1, address=3))
    assert not f(FakeUsbDev(9, 10, bus=1, address=2))
    assert findFromListAndBusDevId(None, None, [1], [10])(FakeUsbDev(1, 10, 5, 6))


def test_devlist_usb_v1x(monkeypatch):
    devs = [FakeUsbDev(kbu.RZ_USB_VEND_ID, kbu.RZ_USB_PROD_ID, 3, 4)]
    seen = {}

    def find(find_all=False, custom_match=None, **kw):
        seen["match"] = custom_match
        return devs
    monkeypatch.setattr(usb.core, "find", find)
    monkeypatch.setattr(usb.util, "get_string", lambda d, i: "str%d" % i)
    out = kbu.devlist_usb_v1x()
    assert out == [["3:4", "str1", "str2"]]
    assert seen["match"](devs[0])
    kbu.devlist_usb_v1x(vendor=1, product=2)


@pytest.mark.parametrize("errno,expect", [(13, "Unable to open device"), (5, None)])
def test_devlist_usb_v1x_errors(monkeypatch, errno, expect):
    class Boom:
        def __iter__(self):
            raise usb.core.USBError("x", errno=errno)
    monkeypatch.setattr(usb.core, "find", lambda **kw: Boom())
    with pytest.raises(Exception) as e:
        kbu.devlist_usb_v1x()
    if expect:
        assert expect in str(e.value)
    else:
        assert isinstance(e.value, usb.core.USBError)


def test_search_usb_none_and_bus(monkeypatch):
    calls = []
    monkeypatch.setattr(usb.core, "find", lambda custom_match=None, **k: calls.append(custom_match) or "dev")
    assert kbu.search_usb(None) == "dev"
    assert kbu.search_usb("1:2") == "dev"
    assert calls[1]._busNum == 1 and calls[1]._devNum == 2


def test_get_serial_ports_include(monkeypatch):
    monkeypatch.setattr(kbu.glob, "glob", lambda p: ["/dev/ttyUSB9"] if "ttyUSB" in p else [])
    assert kbu.get_serial_ports() == ["/dev/ttyUSB9"]
    out = kbu.get_serial_ports(include=["/dev/ttyS5", "192.168.0.1", "/dev/ttyUSB9"])
    assert set(out) == {"/dev/ttyUSB9", "/dev/ttyS5"}


def test_get_serial_devs_stub():
    assert kbu.get_serial_devs([]) is None


def test_issl_nodetest(monkeypatch):
    monkeypatch.setattr(kbu.serial, "Serial",
                        lambda **kw: ScriptSerial([b"x"] * 5 + [b"junk", b"Node Test Application v1"]))
    assert kbu.issl_nodetest("/dev/x") is True
    monkeypatch.setattr(kbu.serial, "Serial", lambda **kw: ScriptSerial([]))
    assert kbu.issl_nodetest("/dev/x") is False


def test_issl_beehive(monkeypatch):
    class BH(ScriptSerial):
        def __init__(self, **kw):
            super().__init__([b"a", b"BeeHive SG 1.0"], **kw)
            self.in_waiting = 1

        def readline(self):
            self.in_waiting = 0
            return super().readline()
    monkeypatch.setattr(kbu.serial, "Serial", lambda **kw: BH())
    assert kbu.issl_beehive("/dev/x") is True
    monkeypatch.setattr(kbu.serial, "Serial", lambda **kw: ScriptSerial([]))
    assert kbu.issl_beehive("/dev/x") is False


def test_isfreakduino(monkeypatch):
    monkeypatch.setattr(kbu.time, "sleep", lambda s: None)
    monkeypatch.setattr(kbu.serial, "Serial", lambda **kw: ScriptSerial(reads=b"abc&C!V7"))
    assert kbu.isfreakduino("/dev/x") is True
    monkeypatch.setattr(kbu.serial, "Serial", lambda **kw: ScriptSerial(reads=b"abc&XXX"))
    assert kbu.isfreakduino("/dev/x") is False


@pytest.mark.xfail(strict=False, reason="GoodFETatmel128.writecmd writes str via serial.write(chr(app)) -> TypeError on py3")
def test_iszigduino_with_fake_goodfet(apimote_env, clean_board):
    assert kbu.iszigduino(apimote_env) is True


def test_iszigduino_serial_error(apimote_env, clean_board):
    with pytest.raises(KBInterfaceError):
        kbu.iszigduino("/dev/does-not-exist")


def test_iszigduino_not_connected(apimote_env, clean_board, monkeypatch):
    from conftest import FakeGoodFETSerial
    monkeypatch.setattr(FakeGoodFETSerial, "accepted_boards", set())
    assert kbu.iszigduino(apimote_env) is False


def test_isgoodfetccspi_apimote2(apimote_env, clean_board):
    assert kbu.isgoodfetccspi(apimote_env) == (True, 2)


def test_isgoodfetccspi_telosb_and_apimote1(apimote_env, clean_board, monkeypatch):
    from conftest import FakeGoodFETSerial
    monkeypatch.setattr(kbu, "DEV_ENABLE_TELOSB", True)
    monkeypatch.setattr(FakeGoodFETSerial, "accepted_boards", {"telosb"})
    monkeypatch.setattr(FakeGoodFETSerial, "telosb_ok", True, raising=False)
    assert kbu.isgoodfetccspi(apimote_env) == (True, 0)
    monkeypatch.setattr(kbu, "DEV_ENABLE_TELOSB", False)
    monkeypatch.setattr(kbu, "DEV_ENABLE_APIMOTE2", False)
    monkeypatch.setattr(kbu, "DEV_ENABLE_APIMOTE1", True)
    monkeypatch.setattr(FakeGoodFETSerial, "accepted_boards", {"apimote1"})
    assert kbu.isgoodfetccspi(apimote_env) == (True, 1)


def test_isgoodfetccspi_nothing_found(apimote_env, clean_board, monkeypatch):
    from conftest import FakeGoodFETSerial
    monkeypatch.setattr(kbu, "DEV_ENABLE_TELOSB", True)
    monkeypatch.setattr(kbu, "DEV_ENABLE_APIMOTE1", True)
    monkeypatch.setattr(FakeGoodFETSerial, "accepted_boards", set())
    assert kbu.isgoodfetccspi(apimote_env) == (False, None)


@pytest.mark.parametrize("flag", ["TELOSB", "APIMOTE2", "APIMOTE1"])
def test_isgoodfetccspi_serial_error(apimote_env, clean_board, monkeypatch, flag):
    for f in ("TELOSB", "APIMOTE2", "APIMOTE1"):
        monkeypatch.setattr(kbu, "DEV_ENABLE_" + f, f == flag)
    with pytest.raises(KBInterfaceError):
        kbu.isgoodfetccspi("/dev/does-not-exist")


def test_devlist_all_types(monkeypatch, capsys):
    monkeypatch.setattr(kbu, "devlist_usb_v1x", lambda v, p: [["1:2", "usbdev", "S"]])
    ports = ["/dev/a", "/dev/b", "/dev/c", "/dev/d", "/dev/gps", "/dev/e", "/dev/f", "/dev/g", "/dev/h"]
    monkeypatch.setattr(kbu, "get_serial_ports", lambda include=None: ports)
    for f in ("SL_NODETEST", "SL_BEEHIVE", "ZIGDUINO", "FREAKDUINO"):
        monkeypatch.setattr(kbu, "DEV_ENABLE_" + f, True)
    monkeypatch.setattr(kbu, "gps_devstring", "/dev/gps")
    monkeypatch.setattr(kbu, "issl_nodetest", lambda d: d == "/dev/a")
    monkeypatch.setattr(kbu, "issl_beehive", lambda d: d == "/dev/b")
    monkeypatch.setattr(kbu, "iszigduino", lambda d: d == "/dev/c")
    monkeypatch.setattr(kbu, "isfreakduino", lambda d: d == "/dev/d")
    subtypes = {"/dev/e": (True, 0), "/dev/f": (True, 1), "/dev/g": (True, 2), "/dev/h": (True, 7)}
    monkeypatch.setattr(kbu, "isgoodfetccspi", lambda d: subtypes[d])
    out = kbu.devlist()
    names = [d[1] for d in out]
    assert names == ["usbdev", "Silabs NodeTest", "BeeHive SG", "Zigduino", "Dartmouth Freakduino",
                     "GoodFET TelosB/Tmote", "GoodFET Api-Mote v1", "GoodFET Api-Mote v2"]
    assert "unknown type of GoodFET CCSPI" in capsys.readouterr().out


def test_devlist_include_ip_and_gps(monkeypatch, capsys):
    import killerbee.dev_sewio as ds
    monkeypatch.setattr(kbu, "devlist_usb_v1x", lambda v, p: [])
    monkeypatch.setattr(kbu, "get_serial_ports", lambda include=None: [])
    monkeypatch.setattr(kbu, "gps_devstring", None)
    monkeypatch.setattr(ds, "isSewio", lambda ip: ip == "10.0.0.1")
    monkeypatch.setattr(ds, "getFirmwareVersion", lambda ip: "1.2")
    monkeypatch.setattr(ds, "getMacAddr", lambda ip: "aa:bb")
    out = kbu.devlist(gps="/dev/gpsdev", include=["10.0.0.1", "10.0.0.2", "/dev/tty0"])
    assert out == [["10.0.0.1", "Sewio Open-Sniffer v1.2", "aa:bb"]]
    assert "unknown type of IP sniffer" in capsys.readouterr().out
    assert kbu.gps_devstring == "/dev/gpsdev"
    kbu.gps_devstring = None


def test_capabilities_frequency_pages():
    c = KBCapabilities()
    for cap in (KBCapabilities.FREQ_863, KBCapabilities.FREQ_868, KBCapabilities.FREQ_870,
                KBCapabilities.FREQ_915, KBCapabilities.FREQ_900, KBCapabilities.FREQ_2400):
        c.setcapab(cap, True)
    assert c.frequency(0, 28) == 863250
    assert c.frequency(1, 29) == 868850
    assert c.frequency(2, 30) == 870650
    assert c.frequency(0, 31) == 915350
    assert c.is_valid_channel(5)            # 900 MHz
    assert not c.is_valid_channel(None)
    assert not c.is_valid_channel(9, 29)
    assert not c.is_valid_channel(5, 40)
    assert c.check(0x99) is False


def test_exceptions():
    assert issubclass(KBInterfaceError, KBException)
