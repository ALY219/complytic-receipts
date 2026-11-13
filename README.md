# complytic-receipts

Tamper-evident execution records for AI agents.

The receipt is sealed before the write executes, signed by a key the agent process
cannot reach in production mode, and verifiable by anyone holding the public key.

**Status: pre-revenue, no client engagements, not independently reviewed.**
See [STATUS.md](STATUS.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Verify it yourself

No account. No access to our systems. No trust required.

```bash
git clone https://github.com/ALY219/complytic-receipts
cd complytic-receipts
pip install -r requirements-dev.txt

python -m complytic_receipts demo     # produce a chain
python -m complytic_receipts verify   # verify against the public key
python -m complytic_receipts tamper   # six attacks, each must be detected
python -m pytest -q                   # 10 unit tests