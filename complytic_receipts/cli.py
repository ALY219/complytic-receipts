"""demo / verify / tamper. Runnable with no cloud account and no second process."""
import argparse, copy, json, os, sqlite3
from .canonical import canon, sha256_hex
from .signer import LocalSigner, RemoteSigner
from .chain import Chain
from .wrapper import SealedConnection
from .verify import verify

OUT = "artifacts"


def _run_chain(signer, chain_id="demo-chain-1"):
    ch = Chain(signer, chain_id, {"principal": "eng-142", "role": "agent_runner"})
    db = SealedConnection(sqlite3.connect(":memory:"), ch, database_label="ledger-demo")
    db.execute("CREATE TABLE ledger (id INTEGER, amount TEXT, vendor TEXT)")
    db.execute("INSERT INTO ledger VALUES (?, ?, ?)", (1, "240000", "SupplierCorp"))
    db.execute("UPDATE ledger SET amount = ? WHERE id = ?", ("245000", 1))
    db.commit()
    return ch


def cmd_demo(a):
    os.makedirs(OUT, exist_ok=True)
    signer = RemoteSigner(a.signer_url) if a.signer_url else LocalSigner(key_path=f"{OUT}/dev_key.pem")
    ch = _run_chain(signer)
    with open(f"{OUT}/chain.json", "w") as f:
        json.dump(ch.envelopes, f, indent=2)
    with open(f"{OUT}/pubkey.pem", "w") as f:
        f.write(signer.public_pem())
    with open(f"{OUT}/meta.json", "w") as f:
        json.dump({"mode": signer.mode, "key_id": signer.key_id,
                   "envelopes": len(ch.envelopes)}, f, indent=2)
    print(f"wrote {OUT}/chain.json  ({len(ch.envelopes)} envelopes)")
    print(f"wrote {OUT}/pubkey.pem")
    print(f"signer mode: {signer.mode}")
    if signer.mode == "local-dev-in-process":
        print("NOTE: in-process key. No isolation. See THREAT_MODEL.md.")
    return 0


def cmd_verify(a):
    with open(a.chain) as f:
        envs = json.load(f)
    with open(a.pubkey) as f:
        pem = f.read()
    r = verify(envs, pem)
    print(f"checked {r['checked']} envelopes")
    print(f"findings:    {r['findings']}")
    print(f"divergences: {r['divergences']}")
    print("RESULT:", "PASS" if r["ok"] else "FAIL")
    return 0 if r["ok"] else 1


def cmd_tamper(a):
    with open(a.chain) as f:
        envs = json.load(f)
    with open(a.pubkey) as f:
        pem = f.read()

    cases = [("clean chain", verify(envs, pem), True)]

    t = copy.deepcopy(envs)
    t[1]["receipt"]["payload"]["sql"] = "INSERT INTO ledger VALUES (1,'999999','Evil')"
    cases.append(("alter SQL after the fact", verify(t, pem), False))

    t = copy.deepcopy(envs)
    t[1]["receipt"]["payload"]["sql"] = "INSERT INTO ledger VALUES (1,'999999','Evil')"
    t[1]["receipt_hash"] = sha256_hex(canon(t[1]["receipt"]))
    cases.append(("rehash without signing key", verify(t, pem), False))

    t = copy.deepcopy(envs)
    del t[1]
    cases.append(("delete a record", verify(t, pem), False))

    t = copy.deepcopy(envs)
    t[1], t[2] = t[2], t[1]
    cases.append(("reorder records", verify(t, pem), False))

    t = copy.deepcopy(envs)
    t[-1]["receipt"]["payload"]["status"] = "rolled_back"
    cases.append(("forge outcome status", verify(t, pem), False))

    print(f"{'ATTACK':38} {'EXPECTED':10} {'RESULT':8} FINDINGS")
    ok = True
    for name, r, should_pass in cases:
        good = (r["ok"] == should_pass)
        ok = ok and good
        print(f"{name:38} {'PASS' if should_pass else 'DETECT':10} "
              f"{'PASS' if r['ok'] else 'DETECT':8} {r['findings'][:2]}")
    print("\nALL TAMPER CASES BEHAVED AS SPECIFIED:", ok)
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="complytic-receipts")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("--signer-url")
    d.set_defaults(f=cmd_demo)
    v = sub.add_parser("verify")
    v.add_argument("--chain", default=f"{OUT}/chain.json")
    v.add_argument("--pubkey", default=f"{OUT}/pubkey.pem")
    v.set_defaults(f=cmd_verify)
    t = sub.add_parser("tamper")
    t.add_argument("--chain", default=f"{OUT}/chain.json")
    t.add_argument("--pubkey", default=f"{OUT}/pubkey.pem")
    t.set_defaults(f=cmd_tamper)
    a = p.parse_args(argv)
    return a.f(a)