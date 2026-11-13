"""Hash-linked, signed receipt chain."""
from datetime import datetime, timezone
from .canonical import GENESIS, CANON_RULE, digest_of
from .signer import ALG

SPEC_VERSION = 1


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Chain:
    def __init__(self, signer, chain_id, actor):
        self.signer, self.chain_id, self.actor = signer, chain_id, dict(actor)
        self.seq, self.prev, self.envelopes = 0, GENESIS, []

    def seal(self, kind, payload, tx_id):
        if kind not in ("intent", "outcome"):
            raise ValueError("kind must be intent or outcome")
        r = {"v": SPEC_VERSION, "chain_id": self.chain_id, "seq": self.seq,
             "prev_hash": self.prev, "kind": kind, "tx_id": tx_id,
             "ts": _utcnow(), "actor": self.actor, "payload": payload}
        h = digest_of(r)
        env = {"receipt": r, "receipt_hash": h,
               "sig": {"alg": ALG, "key_id": self.signer.key_id,
                       "value_b64": self.signer.sign_digest(h),
                       "canonicalization": CANON_RULE}}
        self.seq += 1
        self.prev = h
        self.envelopes.append(env)
        return h