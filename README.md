## Verify it yourself

No account. No access to our systems. No trust required.

```bash
git clone https://github.com/ALY219/complytic-receipts
cd complytic-receipts
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

make verify    # verify the committed chain, no key generation
make tamper    # six attacks, each must be detected
make test      # unit tests
make demo      # generate a fresh chain
```

No `make`? Use the module commands directly:

```bash
python -m complytic_receipts verify
python -m complytic_receipts tamper
python -m pytest -q
python -m complytic_receipts demo
```