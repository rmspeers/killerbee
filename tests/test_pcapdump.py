import io
import struct

import pytest

from killerbee.pcapdump import PcapDumper, PcapReader
from killerbee.daintree import DainTreeDumper, DainTreeReader
import killerbee.pcapdlt as pcapdlt

FRAME = bytes.fromhex("61881234ffff0102030405060708")  # arbitrary 802.15.4-ish bytes


def test_pcapdlt_constants():
    assert pcapdlt.DLT_IEEE802_15_4 == 195
    assert pcapdlt.DLT_PPI == 192
    assert pcapdlt.DLT_NULL == 0


def test_dump_and_read_roundtrip(tmp_path):
    f = tmp_path / "a.pcap"
    d = PcapDumper(pcapdlt.DLT_IEEE802_15_4, str(f))
    d.pcap_dump(FRAME, ts_sec=1000, ts_usec=5)
    d.close()
    r = PcapReader(str(f))
    assert r.datalink() == 195
    hdr, frame = r.pnext()
    assert frame == FRAME
    assert hdr[0] == pytest.approx(1000.000005, abs=1e-9) and hdr[1] == len(FRAME) == hdr[2]
    assert r.pnext() == [None, None]
    r.close()


def test_dump_orig_len_roundtrip(tmp_path):
    f = tmp_path / "ol.pcap"
    d = PcapDumper(195, str(f))
    d.pcap_dump(FRAME, ts_sec=1001, ts_usec=7, orig_len=100)
    d.close()
    r = PcapReader(str(f))
    hdr, frame = r.pnext()
    assert frame == FRAME and hdr[1] == len(FRAME) and hdr[2] == 100
    # libpcap record header: ts_sec, ts_usec, incl_len, orig_len
    raw = f.read_bytes()[24:40]
    assert struct.unpack("<IIII", raw) == (1001, 7, len(FRAME), 100)


def test_dump_default_timestamp_is_now(tmp_path):
    import time

    f = tmp_path / "now.pcap"
    before = time.time()
    with PcapDumper(195, str(f)) as d:
        d.pcap_dump(FRAME)
    hdr, _ = PcapReader(str(f)).pnext()
    assert before - 1 <= hdr[0] <= time.time() + 1


def test_dump_default_timestamp_and_context_manager(tmp_path):
    f = tmp_path / "b.pcap"
    with PcapDumper(195, str(f)) as d:
        d.pcap_dump(FRAME)
    data = f.read_bytes()
    assert len(data) == 24 + 16 + len(FRAME)
    assert struct.unpack("I", data[:4])[0] == 0xA1B2C3D4


def test_dump_to_file_like():
    buf = io.BytesIO()
    d = PcapDumper(195, buf)
    d.pcap_dump(FRAME, ts_sec=1, ts_usec=2)
    assert len(buf.getvalue()) == 24 + 16 + len(FRAME)


def test_dump_bad_savefile():
    with pytest.raises(ValueError):
        PcapDumper(195, 12345)


def test_dump_flush_error():
    class Bad(io.BytesIO):
        def flush(self):
            raise IOError("boom")

    d = PcapDumper(195, Bad())
    with pytest.raises(IOError):
        d.pcap_dump(FRAME, ts_sec=1, ts_usec=2)


def test_ppi_dump(tmp_path):
    f = tmp_path / "ppi.pcap"
    d = PcapDumper(195, str(f), ppi=True)
    d.pcap_dump(FRAME, ts_sec=1, ts_usec=2, freq_mhz=2405, ant_dbm=-40)
    d.pcap_dump(FRAME, ts_sec=1, ts_usec=2)
    d.pcap_dump(FRAME, ts_sec=1, ts_usec=2, location=(-122.4, 37.7, 12.5))
    d.close()
    data = f.read_bytes()
    assert struct.unpack("I", data[20:24])[0] == pcapdlt.DLT_PPI
    r = PcapReader(str(f))
    assert r.datalink() == pcapdlt.DLT_PPI
    hdr, frame = r.pnext()
    assert frame.endswith(FRAME) and len(frame) == len(FRAME) + 32
    hdr, frame = r.pnext()
    hdr, frame = r.pnext()
    assert len(frame) == len(FRAME) + 32 + 24
    r.close()


@pytest.mark.parametrize("loc", [(0, 200, 0), (200, 0, 0), (0, 0, 999999)])
def test_ppi_bad_location(tmp_path, loc):
    d = PcapDumper(195, str(tmp_path / "x.pcap"), ppi=True)
    with pytest.raises(Exception):
        d.pcap_dump(FRAME, ts_sec=1, ts_usec=2, location=loc)


def test_reader_big_endian_file(tmp_path):
    f = tmp_path / "be.pcap"
    f.write_bytes(
        struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 195)
        + struct.pack(">IIII", 5, 250000, 3, 3)
        + b"abc"
    )
    r = PcapReader(str(f))
    assert r.datalink() == 195
    hdr, frame = r.pnext()
    assert hdr == [5.25, 3, 3] and frame == b"abc"
    r.close()


@pytest.mark.parametrize(
    "content",
    [
        struct.pack("<IHHiIII", 0xDEADBEEF, 2, 4, 0, 0, 65535, 195),  # not a pcap magic
        struct.pack("<IHHiIII", 0xA1B2C3D4, 3, 0, 0, 0, 65535, 195),  # unsupported version
        struct.pack("<I", 0xA1B2C3D4),  # truncated header
        b"",
    ],
)
def test_reader_rejects_bad_header(tmp_path, content):
    f = tmp_path / "bad.pcap"
    f.write_bytes(content)
    with pytest.raises(Exception):
        PcapReader(str(f))


def test_reader_oversized_record(tmp_path):
    f = tmp_path / "c.pcap"
    f.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 195)
        + struct.pack("<IIII", 1, 1, 10, 5)
        + b"12345"
    )
    r = PcapReader(str(f))
    with pytest.raises(Exception):
        r.pnext()


# ------------------------------------------------------------ daintree
def test_daintree_roundtrip(tmp_path, capsys):
    f = tmp_path / "x.dcf"
    d = DainTreeDumper(str(f))
    d.pcap_dump(FRAME)
    d.pwrite(FRAME, channel=11, rssi=-5)
    d.close()
    text = f.read_text()
    assert text.startswith("#Format=4")
    r = DainTreeReader(str(f))
    hdr, pkt = r.pnext()
    assert pkt == FRAME
    r.pnext()
    assert r.pnext() == [None, None]
    r.close()


def test_daintree_reader_skips_comment_and_bad_header(tmp_path):
    f = tmp_path / "y.dcf"
    f.write_bytes(b"#Format=4\r\n# comment\r\n1 1.5 2 aabb 255 1 0 26 1 0 1 32767\r\n")
    r = DainTreeReader(str(f))
    hdr, pkt = r.pnext()
    assert pkt == b"\xaa\xbb"
    bad = tmp_path / "z.dcf"
    bad.write_bytes(b"nope\r\n")
    with pytest.raises(Exception):
        DainTreeReader(str(bad))


def test_daintree_closed_handle_errors(tmp_path):
    d = DainTreeDumper(str(tmp_path / "d.dcf"))
    d._fh = None
    with pytest.raises(Exception):
        d.pwrite(FRAME)
    with pytest.raises(Exception):
        d.close()
    r = DainTreeReader.__new__(DainTreeReader)
    r._fh = None
    with pytest.raises(Exception):
        r.pnext()
    with pytest.raises(Exception):
        r.close()
