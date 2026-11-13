import sqlite3, pytest
from complytic_receipts import (LocalSigner, Chain, SealedConnection, verify,
                                canon, sha256_hex)
from complytic_receipts.canonical import CanonicalError


def build():
    s = LocalSigner()
    ch = Chain(s, "t", {"principal": "u1", "role": "runner"})
    db = SealedConnection(sqlite3.connect(":memory:"), ch)
    db.execute("CREATE TABLE t (a INTEGER, b TEXT)")
    db.execute("INSERT INTO t VALUES (?, ?)", (1, "x"))
    db.commit()
    return ch.envelopes, s.public_pem()


def test_clean_passes():
    e, p = build()
    r = verify(e, p)
    assert r["ok"], r["findings"]


def test_intent_sealed_before_execute():
    s = LocalSigner()
    ch = Chain(s, "t", {"principal": "u1", "role": "r"})
    db = SealedConnection(sqlite3.connect(":memory:"), ch)
    db.execute("CREATE TABLE t (a INTEGER)")
    assert ch.envelopes[0]["receipt"]["kind"] == "intent"
    db.commit()
    assert ch.envelopes[-1]["receipt"]["kind"] == "outcome"


def test_alter_detected():
    e, p = build()
    e[1]["receipt"]["payload"]["sql"] = "DROP TABLE t"
    assert not verify(e, p)["ok"]


def test_rehash_without_key_detected():
    e, p = build()
    e[1]["receipt"]["payload"]["sql"] = "DROP TABLE t"
    e[1]["receipt_hash"] = sha256_hex(canon(e[1]["receipt"]))
    r = verify(e, p)
    assert not r["ok"]
    assert any("BAD SIGNATURE" in f for f in r["findings"])


def test_delete_detected():
    e, p = build()
    del e[1]
    assert not verify(e, p)["ok"]


def test_reorder_detected():
    e, p = build()
    e[1], e[2] = e[2], e[1]
    assert not verify(e, p)["ok"]


def test_rollback_produces_outcome():
    s = LocalSigner()
    ch = Chain(s, "t", {"principal": "u1", "role": "r"})
    db = SealedConnection(sqlite3.connect(":memory:"), ch)
    db.execute("CREATE TABLE t (a INTEGER)")
    db.execute("INSERT INTO t VALUES (1)")
    db.rollback()
    r = verify(ch.envelopes, s.public_pem())
    assert r["ok"], r["findings"]
    assert any("rolled_back" in d for d in r["divergences"])


def test_unresolved_transaction_detected():
    s = LocalSigner()
    ch = Chain(s, "t", {"principal": "u1", "role": "r"})
    db = SealedConnection(sqlite3.connect(":memory:"), ch)
    db.execute("CREATE TABLE t (a INTEGER)")
    r = verify(ch.envelopes, s.public_pem())
    assert any("UNRESOLVED" in f for f in r["findings"])


def test_floats_rejected():
    with pytest.raises(CanonicalError):
        canon({"risk": 0.73})


def test_wrong_key_fails():
    e, _ = build()
    other = LocalSigner().public_pem()
    assert not verify(e, other)["ok"]