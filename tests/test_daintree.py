import binascii
import os
import shutil
import unittest

import pytest

from killerbee.daintree import *

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@pytest.fixture(autouse=True)
def _tmp_dir(tmp_path, request):
    """Copy fixtures into tmp_path so the tracked fixture files are never modified."""
    if request.instance is not None:
        request.instance.tmp = str(tmp_path)
        for name in ("test_dt_dump.dcf", "test_dt_read.dcf"):
            shutil.copy(os.path.join(FIXTURES, name), tmp_path / name)
    yield


class TestDaintree(unittest.TestCase):
    def _p(self, name):
        return os.path.join(self.tmp, name)

    def test_daintreedumper_init(self):
        path_to_file = self._p("test_dt_dump.dcf")
        dt = DainTreeDumper(path_to_file)
        dt.close()

        with open(path_to_file) as f:
            self.assertTrue('#Format=4' in f.readline())
            self.assertTrue('# SNA v3.0.0.7 SUS:' in f.readline())

    def test_daintreedumper_pcap_dump(self):
        path_to_file = self._p("dump_pcap.dcf")
        dt = DainTreeDumper(path_to_file)
        dt.pcap_dump(b'\x01\x02\x03', ts_sec=1, ts_usec=2, orig_len=3)
        dt.close()
        with open(path_to_file) as f:
            lines = f.read().splitlines()
        self.assertIn("010203", lines[2])

    def test_daintreedumper_pwrite(self):
        path_to_file = self._p("dump_pwrite.dcf")
        dt = DainTreeDumper(path_to_file)
        dt.pwrite(b'\xde\xad\xbe\xef', channel=11, rssi=5)
        dt.pwrite(b'\x00')
        dt.close()
        with open(path_to_file) as f:
            lines = f.read().splitlines()
        fields = lines[2].split(" ")
        self.assertEqual("1", fields[0])
        self.assertEqual("4", fields[2])
        self.assertEqual("deadbeef", fields[3])
        self.assertEqual("5", fields[6])
        self.assertEqual("11", fields[7])
        self.assertEqual("26", lines[3].split(" ")[7])

    def test_daintreedumper_pwrite_no_handle(self):
        dt = DainTreeDumper(self._p("nohandle.dcf"))
        dt._fh = None
        self.assertRaises(Exception, dt.pwrite, b'\x01')
        self.assertRaises(Exception, dt.close)

    def test_daintreedumper_close(self):
        path_to_file = self._p("test_dt_dump.dcf")
        dt = DainTreeDumper(path_to_file)
        dt.close()

        # handle is gone after close
        self.assertRaises(Exception, dt.close)
        self.assertRaises(Exception, dt.pwrite, b'\x01')

    def test_daintreereader_init(self):
        path_to_file = self._p("test_dt_read.dcf")
        dt = DainTreeReader(path_to_file)
        dt.close()

        self.assertRaises(Exception, DainTreeReader, "/dev/null")

    def test_daintreereader_close(self):
        path_to_file = self._p("test_dt_read.dcf")
        dt = DainTreeReader(path_to_file)
        dt.close()

        self.assertRaises(Exception, dt.close)
        self.assertRaises(Exception, dt.pnext)

    def test_daintreereader_pnext(self):
        path_to_file = self._p("test_dt_read.dcf")
        dt = DainTreeReader(path_to_file)
        out = dt.pnext()
        self.assertAlmostEqual(1623766438.177813, out[0][0], places=3)
        self.assertEqual(binascii.unhexlify(
            "6188ccae287f2c370d48027f2c370d1e0128fd2cf005fabff7020188170000dd727c0549011bcc3828c1a65418d6ea52083257c363"),
            out[1])
        count = 1
        while True:
            out = dt.pnext()
            if out[1] is None:
                break
            count += 1
        self.assertGreaterEqual(count, 2)
        dt.close()

    def test_daintreereader_pnext_skips_comments(self):
        path = self._p("comments.dcf")
        with open(path, "wb") as f:
            f.write(b"#Format=4\r\n# comment line\r\n1 1.5 2 0102 255 1 0 26 1 0 1 32767\r\n")
        dt = DainTreeReader(path)
        out = dt.pnext()
        self.assertEqual(b'\x01\x02', out[1])
        self.assertEqual([None, None], dt.pnext())
        dt.close()

    def test_roundtrip(self):
        path = self._p("roundtrip.dcf")
        dt = DainTreeDumper(path)
        dt.pwrite(b'\x41\x88\x01\x02\x03')
        dt.close()
        rd = DainTreeReader(path)
        self.assertEqual(b'\x41\x88\x01\x02\x03', rd.pnext()[1])
        rd.close()


if __name__ == "__main__":
    unittest.main()
