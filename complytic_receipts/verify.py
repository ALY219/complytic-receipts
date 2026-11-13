"""Verifier. Requires ONLY the public key and the chain. No vendor access."""
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from .canonical import GENESIS, canon, sha256_hex


def verify(envelopes, public_pem):
    findings, divergences = [], []
    try:
        pub = serialization.load_pem_public_key(public_pem.encode())
    except Exception as e:
        return {"ok": False, "findings": [f"BAD PUBLIC KEY: {e}"], "divergences": [], "checked": 0}

    prev, seen_intents, resolved = GENESIS, {}, {}
    for i, e in enumerate(envelopes):
        r = e.get("receipt", {})
        try:
            recomputed = sha256_hex(canon(r))
        except Exception as ex:
            findings.append(f"[{i}] NON-CANONICAL RECEIPT: {ex}")
            continue
        if recomputed != e.get("receipt_hash"):
            findings.append(f"[{i}] HASH MISMATCH")
            continue
        try:
            pub.verify(base64.b64decode(e["sig"]["value_b64"]),
                       bytes.fromhex(e["receipt_hash"]),
                       ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        except InvalidSignature:
            findings.append(f"[{i}] BAD SIGNATURE")
            continue
        except Exception as ex:
            findings.append(f"[{i}] MALFORMED SIGNATURE ({type(ex).__name__})")
            continue
        if r.get("seq") != i:
            findings.append(f"[{i}] SEQ GAP expected={i} got={r.get('seq')}")
        if r.get("prev_hash") != prev:
            findings.append(f"[{i}] CHAIN BREAK")
        prev = e["receipt_hash"]

        if r.get("kind") == "intent":
            seen_intents[e["receipt_hash"]] = r.get("tx_id")
        elif r.get("kind") == "outcome":
            p = r.get("payload", {})
            tx = r.get("tx_id")
            resolved.setdefault(tx, []).append(e["receipt_hash"])
            claimed = [x["intent_hash"] for x in p.get("intents", [])]
            if sha256_hex(canon(claimed)) != p.get("intent_set_sha256"):
                findings.append(f"[{i}] INTENT SET DIGEST MISMATCH")
            for h in claimed:
                if h not in seen_intents:
                    findings.append(f"[{i}] DANGLING INTENT {h[:12]}")
            if p.get("status") != "committed":
                divergences.append(f"[{i}] tx={tx[:8]} status={p.get('status')}")
            for st in p.get("intents", []):
                if st.get("error"):
                    divergences.append(f"[{i}] statement error: {st['error']}")

    for h, tx in seen_intents.items():
        if tx not in resolved:
            findings.append(f"UNRESOLVED TRANSACTION tx={tx[:8]} intent={h[:12]}")
    for tx, outs in resolved.items():
        if len(outs) > 1:
            findings.append(f"MULTIPLE OUTCOMES tx={tx[:8]}")

    return {"ok": not findings, "findings": findings,
            "divergences": divergences, "checked": len(envelopes)}