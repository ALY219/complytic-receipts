"""DBAPI wrapper. Receipts are built from what the DRIVER is handed, not agent self-report."""
import uuid
from .canonical import canon, sha256_hex, digest_of


class SealedConnection:
    def __init__(self, conn, chain, database_label="unknown"):
        self._conn, self._chain, self._db = conn, chain, database_label
        self._tx = str(uuid.uuid4())
        self._intents = []
        self._closed = False

    def _params_digest(self, params):
        if params is None:
            return sha256_hex(canon([]))
        if isinstance(params, dict):
            return digest_of(params)
        return sha256_hex(canon([str(p) for p in params]))

    def execute(self, sql, params=None):
        # SEAL BEFORE the statement runs.
        intent_hash = self._chain.seal("intent", {
            "sql": sql,
            "params_sha256": self._params_digest(params),
            "database": self._db,
            "driver": type(self._conn).__module__,
        }, self._tx)
        rec = {"intent_hash": intent_hash, "sql": sql, "rowcount": None, "error": None}
        self._intents.append(rec)
        try:
            cur = self._conn.execute(sql, params) if params is not None else self._conn.execute(sql)
            rec["rowcount"] = cur.rowcount
            return cur
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
            raise

    def _seal_outcome(self, status, error=None):
        if self._closed:
            return
        self._chain.seal("outcome", {
            "status": status, "error": error,
            "intents": self._intents,
            "intent_set_sha256": sha256_hex(canon([i["intent_hash"] for i in self._intents])),
            "statement_count": len(self._intents),
        }, self._tx)
        self._closed = True

    def commit(self):
        status, err = "committed", None
        try:
            self._conn.commit()
        except Exception as e:
            status, err = "commit_failed", f"{type(e).__name__}: {e}"
            raise
        finally:
            self._seal_outcome(status, err)

    def rollback(self):
        self._conn.rollback()
        self._seal_outcome("rolled_back")

    def close(self):
        self._seal_outcome("closed_without_resolution")
        self._conn.close()