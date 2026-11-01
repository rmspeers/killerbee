import importlib
import sys
import types

import pytest
import scapy.all  # noqa: F401  (ensure scapy importable before DBLogger uses it)

# A frame: data, intra-PAN, short dst/src addrs, seq 7
FRAME = bytes.fromhex("418877cdab01000200aabb")


class FakeCursor:
    """Minimal MySQLdb-like cursor scripted per statement prefix."""

    def __init__(self, db):
        self.db = db
        self.rowcount = 1
        self.lastrowid = 42
        self._fetch = []
        self.closed = False

    def execute(self, sql, params=None):
        self.db.executed.append((sql, params))
        self.rowcount = self.db.rowcounts.get(
            sql.split()[0] + (" " + sql.split()[1] if sql.startswith("INSERT") else ""), 1
        )
        if sql.startswith("SELECT"):
            key = sql.split()[3] if len(sql.split()) > 3 else ""
            self._fetch = list(self.db.selects.get(key, []))
            if sql.startswith("SELECT ds_id"):
                self.rowcount = self.db.ds_rowcount
        self._rows = list(self._fetch)

    def fetchone(self):
        if self._fetch:
            return self._fetch.pop(0)
        return None

    def close(self):
        self.closed = True


class FakeDB:
    def __init__(self):
        self.executed = []
        self.selects = {}
        self.rowcounts = {}
        self.ds_rowcount = 1
        self.commits = 0
        self.cur = FakeCursor(self)

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1


@pytest.fixture
def dblog(monkeypatch):
    fake = types.ModuleType("MySQLdb")
    fake.holder = {"db": FakeDB(), "fail": False, "none": False}

    def connect(**kw):
        if fake.holder["fail"]:
            raise RuntimeError("no db")
        if fake.holder["none"]:
            return None
        fake.holder["kw"] = kw
        return fake.holder["db"]

    fake.connect = connect
    fake.Binary = lambda b: bytes(b)
    monkeypatch.setitem(sys.modules, "MySQLdb", fake)
    sys.modules.pop("killerbee.dblog", None)
    mod = importlib.import_module("killerbee.dblog")
    mod.fake = fake
    yield mod
    sys.modules.pop("killerbee.dblog", None)


def make_logger(dblog, ds_rowcount=1):
    db = dblog.fake.holder["db"]
    db.ds_rowcount = ds_rowcount
    db.selects["datasources"] = [(5,)]
    return dblog.DBLogger("src", channel=11, page=0), db


# ------------------------------------------------------------ DBReader
def test_reader_init_close(dblog):
    r = dblog.DBReader()
    assert r.conn is not None
    r.close()
    assert r.conn is None
    r.close()  # idempotent


def test_reader_init_none_db(dblog):
    dblog.fake.holder["none"] = True
    with pytest.raises(Exception):
        dblog.DBReader()


def test_reader_query_one(dblog):
    r = dblog.DBReader()
    r.conn.execute = lambda sql, params=None: None
    r.conn.rowcount = 1
    r.conn.fetchone = lambda: ("row",)
    assert r.query_one("t", "c", "1=1") == ("row",)
    r.conn.rowcount = 0
    assert r.query_one("t", "c", "1=1") is None


def test_reader_query(dblog):
    r = dblog.DBReader()
    rows = [(1,), (2,)]
    r.conn.execute = lambda sql: setattr(r.conn, "rowcount", len(rows))
    r.conn.fetchone = lambda: rows.pop(0) if rows else None
    assert list(r.query("SELECT 1")) == [(1,), (2,)]
    r.conn.execute = lambda sql: setattr(r.conn, "rowcount", 0)
    assert list(r.query("SELECT 1")) == []


# ------------------------------------------------------------ DBLogger
def test_logger_no_datasource(dblog):
    lg = dblog.DBLogger()
    assert lg.conn is None
    lg.close()


def test_logger_connect_fail(dblog):
    dblog.fake.holder["fail"] = True
    with pytest.raises(Exception) as exc:
        dblog.DBLogger("src")
    # the original error is reported, with no formatting failure
    assert str(exc.value).startswith("DBLogger was unable to connect to the database: no db ")
    assert "config.py" in str(exc.value)


def test_logger_connect_none(dblog):
    dblog.fake.holder["none"] = True
    with pytest.raises(Exception):
        dblog.DBLogger("src")


def test_logger_init_and_close(dblog):
    lg, db = make_logger(dblog)
    assert lg.ds_id == 5
    lg.set_channel(15, 1)
    assert (lg.channel, lg.page) == (15, 1)
    lg.close()
    assert lg.conn is None
    lg.close()
    for fn in (
        lambda: lg.add_location((1, 2, 3)),
        lambda: lg.add_device(1, 2),
        lambda: lg.add_packet(full={}, bytes=FRAME),
    ):
        with pytest.raises(Exception):
            fn()


def test_logger_unknown_datasource(dblog, capsys):
    lg, _ = make_logger(dblog, ds_rowcount=0)
    assert "No datasource found" in capsys.readouterr().out


def test_add_location_existing_and_new(dblog):
    lg, db = make_logger(dblog)
    db.selects["locations"] = [(9,)]
    assert lg.add_location((1.0, 2.0, 3.0)) == 9
    db.selects["locations"] = []
    assert lg.add_location((1.0, 2.0, 3.0)) == 42
    assert db.commits == 1
    db.selects["locations"] = []
    assert lg.add_location((None, None, None)) == 42
    assert any("IS NULL" in s for s, _ in db.executed)
    assert any("longitude = NULL" in s for s, _ in db.executed)


def test_add_location_insert_fail(dblog):
    lg, db = make_logger(dblog)
    db.selects["locations"] = []
    db.rowcounts["INSERT INTO"] = 0
    with pytest.raises(Exception):
        lg.add_location((1.0, 2.0, 3.0))


def test_add_device_existing_new_null(dblog):
    lg, db = make_logger(dblog)
    db.selects["devices"] = [(3,)]
    assert lg.add_device(0x1234, 0xABCD) == 3
    db.selects["devices"] = []
    assert lg.add_device(0x1234, 0xABCD) == 42
    db.selects["devices"] = []
    assert lg.add_device(None, None) == 42
    assert any("short_addr = NULL" in s for s, _ in db.executed)


def test_add_device_insert_fail(dblog):
    lg, db = make_logger(dblog)
    db.selects["devices"] = []
    db.rowcounts["INSERT INTO"] = 0
    with pytest.raises(Exception):
        lg.add_device(1, 2)


def test_insert(dblog):
    lg, db = make_logger(dblog)
    assert lg.insert("INSERT INTO packets SET a=1") == 42
    assert lg.insert("INSERT INTO packets SET a=1", packetbytes=b"\x01") == 42
    assert db.executed[-1][1] == (b"\x01",)
    db.rowcounts["INSERT INTO"] = 0
    with pytest.raises(Exception):
        lg.insert("INSERT INTO packets SET a=1")


class FakeScapy:
    fcf_panidcompress = 1
    fcf_ackreq = 0
    fcf_pending = 0
    fcf_security = 0
    fcf_frametype = 1
    fcf_srcaddrmode = 2
    fcf_framever = 0
    fcf_destaddrmode = 2
    seqnum = 7
    src_addr = 0x1111
    src_panid = 0x2222
    dest_addr = 0x3333
    dest_panid = 0x2222


def test_add_packet_with_fake_scapy(dblog):
    lg, db = make_logger(dblog)
    db.selects["devices"] = [(1,), (2,)]
    db.selects["locations"] = [(4,)]
    lg.page = 2
    out = lg.add_packet(
        full={
            "rssi": -30,
            "datetime": "2020-01-01 00:00:00",
            "location": (1.0, 2.0, 3.0),
            "bytes": FRAME,
        },
        scapy=FakeScapy(),
        channel=20,
        page=3,
    )
    assert out == 42
    sql = db.executed[-1][0]
    assert "seqnum=7" in sql and "rssi=-30" in sql and "cap_datetime" in sql
    assert "loc_id=" in sql and "channel=20" in sql and "page=3" in sql


def test_add_packet_full_none(dblog):
    lg, db = make_logger(dblog)
    lg.add_packet(scapy=FakeScapy(), bytes=FRAME, rssi=-2)
    assert "rssi=-2" in db.executed[-1][0]


def test_add_packet_ids_used_in_sql(dblog):
    lg, db = make_logger(dblog)
    db.selects["devices"] = [(11,)]
    db.selects["locations"] = [(4,)]
    lg.add_packet(full={"location": (1.0, 2.0, 3.0)}, scapy=FakeScapy(), bytes=FRAME)
    sql = db.executed[-1][0]
    assert "ds_id=5," in sql and "source=11" in sql and "dest=11" in sql and "loc_id=4" in sql


def test_add_packet_missing_attrs(dblog):
    lg, db = make_logger(dblog)

    class Bare(FakeScapy):
        def __getattribute__(self, n):
            if n in ("src_addr", "src_panid", "dest_addr", "dest_panid"):
                raise AttributeError(n)
            return object.__getattribute__(self, n)

    lg.add_packet(full={}, scapy=Bare(), bytes=FRAME, rssi=-1)
    assert "rssi=-1" in db.executed[-1][0]


def test_add_packet_real_scapy(dblog):
    lg, db = make_logger(dblog)
    db.selects["devices"] = [(1,), (2,)]
    # Real Dot15d4 dissection of a data frame (scapy imported lazily in add_packet)
    frame = bytes.fromhex("61880122340100ffff0000aabb")
    lg.add_packet(full={}, bytes=frame)
    sql = db.executed[-1][0]
    assert "fcf_frametype=1" in sql and "seqnum=1" in sql
