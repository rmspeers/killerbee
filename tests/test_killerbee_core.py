import argparse
import os
import struct
import unittest

import pytest

from killerbee import *
from killerbee.dev_apimote import APIMOTE


@pytest.mark.usefixtures("apimote_env")
class TestKillerbeeCore(unittest.TestCase):
    def test_show_dev(self):
        show_dev()
        self.assertTrue(True)

    def test_killerbee_init(self):
        devstring = os.environ["APIMOTE_DEVSTRING"]

        # TODO datastore, gps, dblog

        # TODO usbserial throws exception
        kb = KillerBee()
        self.assertRaises(Exception, KillerBee, "/dev/null")

        # APIMOTE only
        kb = KillerBee(devstring)
        self.assertIsNotNone(kb.driver)
        self.assertIsNotNone(kb.driver.handle)
        self.assertIsNotNone(kb.dev)
        self.assertEqual(kb.dev, devstring)

        kb.close()

    def test_killerbee_close(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])
        self.assertIsNotNone(kb.driver.handle)
        kb.close()
        self.assertIsNone(kb.driver.handle)

    def test_killerbee_get_dev_info(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        info = kb.get_dev_info()

        self.assertEqual(os.environ["APIMOTE_DEVSTRING"], info[0])
        self.assertEqual("GoodFET Apimote v2", info[1])
        self.assertEqual("", info[2])

        kb.close()

    def test_killerbee_check_capability(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertTrue(kb.check_capability(KBCapabilities.FREQ_2400))
        self.assertTrue(kb.check_capability(KBCapabilities.SNIFF))
        self.assertTrue(kb.check_capability(KBCapabilities.SETCHAN))
        self.assertTrue(kb.check_capability(KBCapabilities.INJECT))
        self.assertTrue(kb.check_capability(KBCapabilities.PHYJAM_REFLEX))
        self.assertTrue(kb.check_capability(KBCapabilities.SET_SYNC))
        self.assertTrue(kb.check_capability(KBCapabilities.PHYJAM))
        self.assertFalse(kb.check_capability(KBCapabilities.NONE))
        self.assertFalse(kb.check_capability(KBCapabilities.SELFACK))
        self.assertFalse(kb.check_capability(KBCapabilities.FREQ_900))
        self.assertFalse(kb.check_capability(KBCapabilities.FREQ_863))
        self.assertFalse(kb.check_capability(KBCapabilities.FREQ_868))
        self.assertFalse(kb.check_capability(KBCapabilities.FREQ_870))
        self.assertFalse(kb.check_capability(KBCapabilities.FREQ_915))
        self.assertFalse(kb.check_capability(KBCapabilities.BOOT))

        kb.close()

    def test_killerbee_is_valid_channel(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertFalse(kb.is_valid_channel(27, 28))
        self.assertFalse(kb.is_valid_channel(26, 28))
        self.assertFalse(kb.is_valid_channel(9, 29))
        self.assertFalse(kb.is_valid_channel(8, 29))
        self.assertFalse(kb.is_valid_channel(8, 29))
        self.assertFalse(kb.is_valid_channel(27, 30))
        self.assertFalse(kb.is_valid_channel(26, 30))
        self.assertFalse(kb.is_valid_channel(27, 31))
        self.assertFalse(kb.is_valid_channel(26, 31))
        self.assertFalse(kb.is_valid_channel(1, 27))
        self.assertFalse(kb.is_valid_channel(1, 32))
        self.assertFalse(kb.is_valid_channel(1))
        self.assertFalse(kb.is_valid_channel(10))
        self.assertFalse(kb.is_valid_channel(27))
        self.assertTrue(kb.is_valid_channel(11))
        self.assertTrue(kb.is_valid_channel(26))

        kb.close()

    def test_killerbee_frequency(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertEqual(0, kb.frequency(11, 1))
        self.assertEqual(0, kb.frequency(1))
        self.assertEqual(0, kb.frequency(27))
        self.assertEqual(2405000, kb.frequency(11))
        self.assertEqual(2405000, kb.frequency(11, 0))
        self.assertEqual(2480000, kb.frequency(26))
        self.assertEqual(2480000, kb.frequency(26, 0))

        # TODO frequency handles none-case
        # self.assertEqual(0, kb.frequency())

        kb.close()

    def test_killerbee_get_capabilities(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])
        capabilities = kb.get_capabilities()

        self.assertTrue(capabilities[KBCapabilities.SNIFF])
        self.assertTrue(capabilities[KBCapabilities.SETCHAN])
        self.assertTrue(capabilities[KBCapabilities.INJECT])
        self.assertTrue(capabilities[KBCapabilities.PHYJAM_REFLEX])
        self.assertTrue(capabilities[KBCapabilities.SET_SYNC])
        self.assertTrue(capabilities[KBCapabilities.FREQ_2400])
        self.assertTrue(capabilities[KBCapabilities.PHYJAM])
        self.assertFalse(capabilities[KBCapabilities.NONE])
        self.assertFalse(capabilities[KBCapabilities.SELFACK])
        self.assertFalse(capabilities[KBCapabilities.FREQ_900])
        self.assertFalse(capabilities[KBCapabilities.FREQ_863])
        self.assertFalse(capabilities[KBCapabilities.FREQ_868])
        self.assertFalse(capabilities[KBCapabilities.FREQ_870])
        self.assertFalse(capabilities[KBCapabilities.FREQ_915])
        self.assertFalse(capabilities[KBCapabilities.BOOT])

    def test_killerbee_enter_bootloader(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(AttributeError, kb.enter_bootloader)

        kb.close()

    def test_killerbee_get_bootloader_version(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(AttributeError, kb.get_bootloader_version)

        kb.close()

    def test_killerbee_get_bootloader_signature(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(AttributeError, kb.get_bootloader_signature)

        kb.close()

    def test_killerbee_bootloader_sign_on(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(AttributeError, kb.bootloader_sign_on)

        kb.close()

    def test_killerbee_bootloader_start_application(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(AttributeError, kb.bootloader_start_application)

        kb.close()

    def test_killerbee_sniffer_on_off(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])
        kb.sniffer_on()

        kb.sniffer_off()

        kb.close()

        self.assertTrue(True)

    def test_killerbee_channel(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertEqual(None, kb.channel)

        kb.set_channel(15)

        self.assertEqual(15, kb.channel)

        kb.close()

    def test_killerbee_page(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertEqual(0, kb.page)

        # kb.set_channel(15, 5)

        # self.assertEqual(5, kb.page)

        kb.close()

    def test_killerbee_set_channel(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertEqual(None, kb.channel)

        kb.set_channel(15)

        self.assertEqual(15, kb.channel)

        self.assertRaises(ValueError, kb.set_channel, 15, 5)

        kb.close()

    def test_killerbee_inject(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(Exception, kb.inject, b"")

        packet = struct.pack("<126s", (b"\x01" * 126))
        self.assertRaises(Exception, kb.inject, packet)

        packet = struct.pack("<100s", (b"\x01" * 100))
        kb.inject(packet)

        kb.close()

    def test_killerbee_pnext(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        fake = None
        if os.environ["APIMOTE_DEVSTRING"] == "/dev/ttyFAKE0":
            from conftest import FakeGoodFETSerial

            fake = FakeGoodFETSerial.last
            fake.queue_packet(bytes([3]) + b"\x01\x02\x03")

        kb.set_channel(25)
        result = kb.pnext(timeout=1)

        if fake is not None:
            self.assertEqual(result["bytes"], b"\x01\x02\x03")

        kb.close()

    def test_killerbee_jammer_on_off(self):
        kb = KillerBee(os.environ["APIMOTE_DEVSTRING"])

        # kb.jammer_on(None, 'reflexive')
        # kb.jammer_on(None, 'constant')
        # kb.jammer_on(11, 'constant')
        self.assertRaises(Exception, kb.jammer_on, None, 0, "none")
        self.assertRaises(Exception, kb.jammer_off)

        kb.close()


# ---------------------------------------------------------------------------
# Additional mock-driven tests of KillerBee driver selection and delegation
# ---------------------------------------------------------------------------
import sys
import types
from unittest import mock

import killerbee as kbmod
from killerbee import kbutils


class DummyDriver:
    """Stands in for every dev_* driver class."""

    VARIANT_CC2530 = 1
    VARIANT_CC2531 = 2

    def __init__(self, *args, **kw):
        self.args = args
        self.kw = kw
        self.closed = False
        self._channel = None
        self._page = 0
        self.capabilities = kbutils.KBCapabilities()
        self.capabilities.setcapab(kbutils.KBCapabilities.FREQ_2400, True)

    def close(self):
        self.closed = True

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **k: (name, a, k)


def _patch_driver(monkeypatch, module, cls):
    import importlib

    m = importlib.import_module("killerbee." + module)
    monkeypatch.setattr(m, cls, DummyDriver)


HARDWARE = [
    ("apimote", "dev_apimote", "APIMOTE"),
    ("rzusbstick", "dev_rzusbstick", "RZUSBSTICK"),
    ("cc2530", "dev_cc253x", "CC253x"),
    ("cc2531", "dev_cc253x", "CC253x"),
    ("bumblebee", "dev_bumblebee", "Bumblebee"),
    ("sl_nodetest", "dev_sl_nodetest", "SL_NODETEST"),
    ("sl_beehive", "dev_sl_beehive", "SL_BEEHIVE"),
    ("zigduino", "dev_zigduino", "ZIGDUINO"),
    ("freakdruino", "dev_freakduino", "FREAKDUINO"),
    ("telosb", "dev_telosb", "TELOSB"),
    ("sewio", "dev_sewio", "SEWIO"),
]


@pytest.mark.parametrize("hardware,module,cls", HARDWARE)
def test_explicit_hardware(monkeypatch, hardware, module, cls):
    _patch_driver(monkeypatch, module, cls)
    kb = KillerBee("dev0", hardware=hardware)
    assert isinstance(kb.driver, DummyDriver)


def test_explicit_unknown_hardware_raises():
    with pytest.raises(KBInterfaceError):
        KillerBee("dev0", hardware="nonexistent")


USB_IDS = [
    (kbutils.RZ_USB_VEND_ID, kbutils.RZ_USB_PROD_ID, "dev_rzusbstick", "RZUSBSTICK"),
    (kbutils.CC2530_USB_VEND_ID, kbutils.CC2530_USB_PROD_ID, "dev_cc253x", "CC253x"),
    (kbutils.CC2531_USB_VEND_ID, kbutils.CC2531_USB_PROD_ID, "dev_cc253x", "CC253x"),
    (kbutils.BB_USB_VEND_ID, kbutils.BB_USB_PROD_ID, "dev_bumblebee", "Bumblebee"),
]


@pytest.mark.parametrize("vid,pid,module,cls", USB_IDS)
@pytest.mark.parametrize("device", [None, "1:2"])
def test_usb_detection(monkeypatch, vid, pid, module, cls, device):
    _patch_driver(monkeypatch, module, cls)
    dev = types.SimpleNamespace(idVendor=vid, idProduct=pid)
    monkeypatch.setattr(kbmod, "search_usb", lambda d: dev)
    kb = KillerBee(device)
    assert isinstance(kb.driver, DummyDriver)


def test_usb_search_uses_requested_bus_device(monkeypatch):
    seen = []
    _patch_driver(monkeypatch, "dev_rzusbstick", "RZUSBSTICK")
    dev = types.SimpleNamespace(idVendor=kbutils.RZ_USB_VEND_ID, idProduct=kbutils.RZ_USB_PROD_ID)
    monkeypatch.setattr(kbmod, "search_usb", lambda d: seen.append(d) or dev)
    KillerBee("3:7")
    assert seen == ["3:7"]


def test_usb_zena_and_unknown(monkeypatch):
    zena = types.SimpleNamespace(idVendor=kbutils.ZN_USB_VEND_ID, idProduct=kbutils.ZN_USB_PROD_ID)
    monkeypatch.setattr(kbmod, "search_usb", lambda d: zena)
    with pytest.raises(KBInterfaceError, match="Zena"):
        KillerBee()
    other = types.SimpleNamespace(idVendor=1, idProduct=2)
    monkeypatch.setattr(kbmod, "search_usb", lambda d: other)
    with pytest.raises(KBInterfaceError, match="doesn't know how"):
        KillerBee()


def test_usb_not_found(monkeypatch):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    with pytest.raises(KBInterfaceError, match="Did not find a USB"):
        KillerBee("1:2")


def test_ip_device(monkeypatch):
    import killerbee.dev_sewio as ds

    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(ds, "isSewio", lambda ip: True)
    monkeypatch.setattr(ds, "SEWIO", DummyDriver)
    kb = KillerBee("10.1.2.3")
    assert isinstance(kb.driver, DummyDriver)


def test_ip_device_not_sewio(monkeypatch):
    import killerbee.dev_sewio as ds

    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(ds, "isSewio", lambda ip: False)
    with pytest.raises(KBInterfaceError, match="cannot find device"):
        KillerBee("10.1.2.3")


SERIAL_CASES = [
    ("DEV_ENABLE_SL_NODETEST", "issl_nodetest", "dev_sl_nodetest", "SL_NODETEST"),
    ("DEV_ENABLE_SL_BEEHIVE", "issl_beehive", "dev_sl_beehive", "SL_BEEHIVE"),
    ("DEV_ENABLE_ZIGDUINO", "iszigduino", "dev_zigduino", "ZIGDUINO"),
    ("DEV_ENABLE_FREAKDUINO", "isfreakduino", "dev_freakduino", "FREAKDUINO"),
]


@pytest.mark.parametrize("flag,probe,module,cls", SERIAL_CASES)
def test_serial_probe_selection(monkeypatch, flag, probe, module, cls):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod, flag, True)
    monkeypatch.setattr(kbmod, probe, lambda d: True)
    _patch_driver(monkeypatch, module, cls)
    kb = KillerBee("/dev/ttyUSB5")
    assert isinstance(kb.driver, DummyDriver)


@pytest.mark.parametrize(
    "result,module,cls",
    [((True, 0), "dev_telosb", "TELOSB"), ((True, 2), "dev_apimote", "APIMOTE")],
)
def test_serial_goodfet_selection(monkeypatch, result, module, cls):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod, "isgoodfetccspi", lambda d: result)
    _patch_driver(monkeypatch, module, cls)
    kb = KillerBee("/dev/ttyUSB5")
    assert isinstance(kb.driver, DummyDriver)


def test_serial_unknown_device(monkeypatch):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod, "isgoodfetccspi", lambda d: (False, None))
    with pytest.raises(KBInterfaceError, match="doesn't know how"):
        KillerBee("/dev/ttyUSB5")


def test_serial_gps_skipped(monkeypatch):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod.kbutils, "gps_devstring", None)
    with pytest.raises(KBInterfaceError, match="cannot find device"):
        KillerBee("/dev/ttyUSB5", gps="/dev/ttyUSB5")
    assert kbmod.kbutils.gps_devstring == "/dev/ttyUSB5"


def test_no_device_uses_first_serial_port(monkeypatch):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod, "get_serial_ports", lambda: ["/dev/ttyUSB7"])
    monkeypatch.setattr(kbmod, "isgoodfetccspi", lambda d: (True, 2))
    _patch_driver(monkeypatch, "dev_apimote", "APIMOTE")
    assert KillerBee().dev == "/dev/ttyUSB7"


def test_no_device_bad_serial_string(monkeypatch):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod, "get_serial_ports", lambda: ["weird"])
    with pytest.raises(KBInterfaceError, match="understand"):
        KillerBee()


def test_no_device_nothing_found(monkeypatch):
    monkeypatch.setattr(kbmod, "search_usb", lambda d: None)
    monkeypatch.setattr(kbmod, "get_serial_ports", lambda: [])
    with pytest.raises(KBInterfaceError, match="cannot find"):
        KillerBee()


@pytest.fixture
def dbl(monkeypatch):
    """killerbee.dblog imported against a stub MySQLdb (not installed here)."""
    monkeypatch.setitem(sys.modules, "MySQLdb", mock.MagicMock())
    had = "killerbee.dblog" in sys.modules
    import killerbee.dblog as mod

    yield mod
    if not had:
        sys.modules.pop("killerbee.dblog", None)
        if hasattr(kbmod, "dblog"):
            delattr(kbmod, "dblog")


def test_datasource_dblog(monkeypatch, dbl):
    created = []

    class FakeDB:
        def __init__(self, ds):
            created.append(ds)
            self.chan = []
            self.closed = False

        def set_channel(self, c, p):
            self.chan.append((c, p))

        def close(self):
            self.closed = True

    monkeypatch.setattr(dbl, "DBLogger", FakeDB)
    _patch_driver(monkeypatch, "dev_apimote", "APIMOTE")
    kb = KillerBee("d", hardware="apimote", datasource="unit")
    assert created == ["unit"]
    kb.set_channel(15)
    assert kb.dblog.chan == [(15, 0)]
    kb.close()
    assert kb.dblog.closed


def test_datasource_dblog_error_is_warning(monkeypatch, dbl):
    def boom(ds):
        raise RuntimeError("no db")

    monkeypatch.setattr(dbl, "DBLogger", boom)
    _patch_driver(monkeypatch, "dev_apimote", "APIMOTE")
    with pytest.warns(UserWarning, match="DBLogger"):
        KillerBee("d", hardware="apimote", datasource="unit")


def test_context_manager_and_delegation(monkeypatch):
    _patch_driver(monkeypatch, "dev_apimote", "APIMOTE")
    with KillerBee("d", hardware="apimote") as kb:
        drv = kb.driver
        assert kb.get_dev_info()[0] == "get_dev_info"
        assert kb.enter_bootloader()[0] == "enter_bootloader"
        assert kb.get_bootloader_version()[0] == "get_bootloader_version"
        assert kb.get_bootloader_signature()[0] == "get_bootloader_signature"
        assert kb.bootloader_sign_on()[0] == "bootloader_sign_on"
        assert kb.bootloader_start_application()[0] == "bootloader_start_application"
        assert kb.sniffer_on(11)[0] == "sniffer_on"
        assert kb.sniffer_off()[0] == "sniffer_off"
        assert kb.inject(b"x", 11, 1, 0, 0)[0] == "inject"
        assert kb.pnext(5)[0] == "pnext"
        assert kb.jammer_on(11, "constant")[0] == "jammer_on"
        assert kb.jammer_off()[0] == "jammer_off"
        assert kb.frequency(11) == 2405000
        assert kb.page == 0
        assert kb.channel is None
    assert drv.closed


def test_no_driver_errors(monkeypatch):
    _patch_driver(monkeypatch, "dev_apimote", "APIMOTE")
    kb = KillerBee("d", hardware="apimote")
    kb.driver = None
    for call in (
        kb.get_dev_info,
        kb.close,
        lambda: kb.check_capability(1),
        lambda: kb.is_valid_channel(11),
        kb.frequency,
        kb.get_capabilities,
        kb.enter_bootloader,
        kb.get_bootloader_version,
        kb.get_bootloader_signature,
        kb.bootloader_sign_on,
        kb.bootloader_start_application,
        kb.sniffer_on,
        kb.sniffer_off,
        lambda: kb.channel,
        lambda: kb.page,
        lambda: kb.set_channel(11),
        lambda: kb.inject(b"x"),
        kb.pnext,
        kb.jammer_on,
        kb.jammer_off,
    ):
        with pytest.raises(KBInterfaceError):
            call()


def test_show_dev_prints(monkeypatch, capsys):
    monkeypatch.setattr(kbmod, "devlist", lambda **kw: [["a", "prod", None], ["b", "p2", "sn"]])
    show_dev(vendor=1, product=2, gps="g", include=["x"])
    out = capsys.readouterr().out
    assert "Product String" in out and "prod" in out and "None" in out


if __name__ == "__main__":
    unittest.main()
