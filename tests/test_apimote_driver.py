import argparse
import os
import struct
import unittest

import pytest

from killerbee.dev_apimote import APIMOTE
from killerbee.kbutils import KBCapabilities, makeFCS


@pytest.mark.usefixtures("apimote_env")
class TestApimoteDriver(unittest.TestCase):
    def test_init(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        self.assertEqual("apimote2", os.environ["platform"])
        self.assertEqual("apimote2", os.environ["board"])
        self.assertIsNotNone(driver.handle)

        driver.close()

    def test_close(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        self.assertIsNotNone(driver.handle)
        driver.close()
        self.assertIsNone(driver.handle)

    def test_get_capabilities(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        capabilities = driver.get_capabilities()
        self.assertTrue(capabilities[KBCapabilities.FREQ_2400])
        self.assertTrue(capabilities[KBCapabilities.SNIFF])
        self.assertTrue(capabilities[KBCapabilities.SETCHAN])
        self.assertTrue(capabilities[KBCapabilities.INJECT])
        self.assertTrue(capabilities[KBCapabilities.PHYJAM_REFLEX])
        self.assertTrue(capabilities[KBCapabilities.SET_SYNC])
        self.assertFalse(capabilities[KBCapabilities.NONE])
        self.assertFalse(capabilities[KBCapabilities.SELFACK])
        self.assertTrue(capabilities[KBCapabilities.PHYJAM])
        self.assertFalse(capabilities[KBCapabilities.FREQ_900])
        self.assertFalse(capabilities[KBCapabilities.FREQ_863])
        self.assertFalse(capabilities[KBCapabilities.FREQ_868])
        self.assertFalse(capabilities[KBCapabilities.FREQ_870])
        self.assertFalse(capabilities[KBCapabilities.FREQ_915])
        self.assertFalse(capabilities[KBCapabilities.BOOT])

        driver.close()

    def test_get_dev_info(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        info = driver.get_dev_info()
        self.assertEqual(os.environ["APIMOTE_DEVSTRING"], info[0])
        self.assertEqual("GoodFET Apimote v2", info[1])
        self.assertEqual("", info[2])

        driver.close()

    def test_check_capabilities(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        self.assertTrue(driver.check_capability(KBCapabilities.FREQ_2400))
        self.assertTrue(driver.check_capability(KBCapabilities.SNIFF))
        self.assertTrue(driver.check_capability(KBCapabilities.SETCHAN))
        self.assertTrue(driver.check_capability(KBCapabilities.INJECT))
        self.assertTrue(driver.check_capability(KBCapabilities.PHYJAM_REFLEX))
        self.assertTrue(driver.check_capability(KBCapabilities.SET_SYNC))
        self.assertFalse(driver.check_capability(KBCapabilities.NONE))
        self.assertFalse(driver.check_capability(KBCapabilities.SELFACK))
        self.assertTrue(driver.check_capability(KBCapabilities.PHYJAM))
        self.assertFalse(driver.check_capability(KBCapabilities.FREQ_900))
        self.assertFalse(driver.check_capability(KBCapabilities.FREQ_863))
        self.assertFalse(driver.check_capability(KBCapabilities.FREQ_868))
        self.assertFalse(driver.check_capability(KBCapabilities.FREQ_870))
        self.assertFalse(driver.check_capability(KBCapabilities.FREQ_915))
        self.assertFalse(driver.check_capability(KBCapabilities.BOOT))

        driver.close()

    def test_sniffer_on_off(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        driver.sniffer_on()

        driver.sniffer_off()

        driver.close()
        self.assertTrue(True)

    def test_set_channel(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(Exception, driver.set_channel, 1)
        self.assertRaises(Exception, driver.set_channel, 27)

        driver.set_channel(11)
        self.assertEqual(driver._channel, 11)

        driver.set_channel(15)
        self.assertEqual(driver._channel, 15)

        driver.set_channel(26)
        self.assertEqual(driver._channel, 26)

        driver.close()

    def test_inject(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(Exception, driver.inject, b"")

        packet = struct.pack("<126s", (b"\x01" * 126))
        self.assertRaises(Exception, driver.inject, packet)

        packet = struct.pack("<100s", (b"\x01" * 100))
        driver.inject(packet)

        driver.close()

    def test_pnext(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        fake = self._fake()
        if fake is not None:
            fake.queue_packet(bytes([5]) + b"\x01\x02\x03\x04\x05")
            fake.regs[0x13] = 0x10

        driver.set_channel(25)
        result = driver.pnext(timeout=1)
        if fake is not None:
            self.assertEqual(result["bytes"], b"\x01\x02\x03\x04\x05")
            self.assertFalse(result["validcrc"])
            self.assertEqual(result[2], 0x10 ^ 0x80)
            self.assertEqual(result["dbm"], result["rssi"] - 45)
            self.assertIsNone(result["location"])
            # nothing else queued: timeout -> None
            self.assertIsNone(driver.pnext(timeout=0))

        driver.close()

    def test_pnext_valid_crc_and_queued_packet(self):
        if self._fake_env() is None:
            self.skipTest("needs fake device")
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        fake = self._fake()
        body = b"\x01\x02\x03"
        frame = body + makeFCS(body)
        second = b"\xaa\xbb\xcc"
        # one read returns two frames back to back
        fake.queue_packet(bytes([len(frame)]) + frame + bytes([len(second)]) + second)
        first = driver.pnext(timeout=1)
        self.assertTrue(first["validcrc"])
        self.assertEqual(first["bytes"], frame)
        queued = driver.pnext(timeout=1)
        self.assertEqual(queued["bytes"], second)
        self.assertIsNone(driver.packet_queue)
        driver.close()

    def test_pnext_queued_without_rssi(self):
        if self._fake_env() is None:
            self.skipTest("needs fake device")
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        fake = self._fake()
        driver.packet_queue = b"\x02\x01\x02"  # <len><frame> wire format
        driver.packet_queue_rssi = None
        result = driver.pnext()
        self.assertEqual(result["bytes"], b"\x01\x02")
        self.assertIsNone(result["rssi"])
        self.assertIsNone(result["dbm"])
        driver.close()

    def test_handle_none_errors(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        driver.close()
        self.assertRaises(Exception, driver.close)
        self.assertRaises(Exception, driver.sniffer_on)
        self.assertRaises(Exception, driver.set_channel, 11)
        self.assertRaises(Exception, driver.inject, b"\x01")
        self.assertRaises(Exception, driver.pnext)
        self.assertRaises(Exception, driver.jammer_on)
        self.assertRaises(Exception, driver.set_sync)

    def test_sniffer_on_with_channel_and_page(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        driver.sniffer_on(channel=12)
        self.assertEqual(driver._channel, 12)
        self.assertRaises(Exception, driver.sniffer_on, 12, 1)
        driver.close()

    def test_inject_channel_count(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        driver.inject(b"\x01\x02", channel=13, count=2)
        self.assertEqual(driver._channel, 13)
        fake = self._fake()
        if fake is not None:
            self.assertEqual(len(fake.tx_packets), 2)
            self.assertEqual(fake.tx_packets[0], bytes([4, 1, 2]))
        driver.close()

    def test_jammer_methods(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        fake = self._fake()
        if fake is None:
            self.skipTest("jamming would transmit on real hardware")
        driver.jammer_on()  # default: constant carrier
        driver.jammer_on(11, 0, "constant")
        self.assertEqual(driver._channel, 11)
        driver.jammer_on(None, 0, "reflexive")
        self.assertIn(0xA0, [v for (_a, v, _d) in fake.sent])
        self.assertIn(0x2E, fake.regs)  # DACTST set by carrier
        driver.close()

    def test_set_sync_value(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
        fake = self._fake()
        driver.set_sync(0x1234)
        if fake is not None:
            self.assertEqual(fake.regs[0x14], 0x1234)
        driver.set_sync()
        driver.close()

    @staticmethod
    def _fake_env():
        return True if os.environ.get("APIMOTE_DEVSTRING") == "/dev/ttyFAKE0" else None

    @staticmethod
    def _fake():
        """Return the live FakeGoodFETSerial, or None on real hardware."""
        from conftest import FakeGoodFETSerial

        if os.environ.get("APIMOTE_DEVSTRING") != "/dev/ttyFAKE0":
            return None
        return FakeGoodFETSerial.last

    def test_ping(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(Exception, driver.ping)

    def test_jammer_on_off(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        # driver.jammer_on(None, 0, 'reflexive')
        # driver.jammer_on(None, 0, 'constant')
        # driver.jammer_on(11, 0, 'constant')
        self.assertRaises(Exception, driver.jammer_on, None, 0, "none")
        self.assertRaises(Exception, driver.jammer_off)

        driver.close()

    def test_set_sync(self):
        driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])

        self.assertRaises(Exception, driver.set_sync, 0x0123456)

        driver.set_sync(0x1234)

        driver.close()


@pytest.mark.hardware
def test_real_apimote_smoke():
    """Runs only when APIMOTE_DEVSTRING points at a real Apimote."""
    driver = APIMOTE(os.environ["APIMOTE_DEVSTRING"])
    assert driver.get_dev_info()[1] == "GoodFET Apimote v2"
    driver.set_channel(15)
    driver.close()


if __name__ == "__main__":
    unittest.main()
