# Complytic receipts — convenience targets.
# Windows: make is not installed by default. Use the python -m commands directly.
# Override the interpreter with:  make demo PY=python3

PY ?= python

.PHONY: help install demo verify tamper test isolated clean

help:
	@echo "make install   - install dev dependencies"
	@echo "make demo      - produce a receipt chain"
	@echo "make verify    - verify chain against the public key"
	@echo "make tamper    - run six tamper attacks, each must be detected"
	@echo "make test      - run unit tests"
	@echo "make isolated  - start the signer in a separate process"
	@echo "make clean     - remove generated key and caches"

install:
	$(PY) -m pip install -r requirements-dev.txt

demo:
	$(PY) -m complytic_receipts demo

verify:
	$(PY) -m complytic_receipts verify

tamper:
	$(PY) -m complytic_receipts tamper

test:
	$(PY) -m pytest -q

isolated:
	$(PY) signer_service.py

clean:
	$(PY) -c "import shutil,os; [shutil.rmtree(p,ignore_errors=True) for p in ['__pycache__','.pytest_cache','complytic_receipts/__pycache__','tests/__pycache__']]; os.path.exists('artifacts/dev_key.pem') and os.remove('artifacts/dev_key.pem')"